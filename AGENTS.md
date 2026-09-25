# AGENTS.md — Contributor & AI-Agent Standards

> **Reference Architecture — Clean Architecture Over Operational Continuity.** CAGE
> demonstrates governance patterns for AI systems. Because CAGE is a reference
> architecture and not a deployed production service, **breaking changes and
> operational considerations are far less important than a clean, legible
> architecture.** The optimization target is clean code structure, modularity,
> and architectural clarity — not operational safety, uptime, or backward
> compatibility. There is no live production instance to protect. Breaking
> changes are therefore **acceptable and often desirable**: they remove designs
> the project is deliberately moving away from, and no deprecation window is owed
> to anyone. Where a choice exists between operational completeness and
> structural clarity, always choose structural clarity. Deployment,
> change-management, and region-guard rules describe illustrative models for
> adopters to adapt to their own environments, not operational constraints that
> compromise the cleanliness of the codebase.

This file defines standards for anyone (human or AI coding agent) contributing
to this repository. It is written in the tool-agnostic `AGENTS.md` convention
supported natively by most AI coding assistants (including Antigravity, Roo Code,
Cursor, Cline, GitHub Copilot, and Windsurf) — see
[Tool-Specific Configuration](#tool-specific-configuration) at the bottom.

## Table of Contents

1. [Commit Message Standard](#commit-message-standard)
2. [Branch Naming & Merge Strategy](#branch-naming--merge-strategy)
3. [Code Standards](#code-standards)
4. [Deployment Rules](#deployment-rules)
5. [Debugging Standards](#debugging-standards)
6. [Compliance Artifact Obligations](#compliance-artifact-obligations)
7. [Architecture & Design Standards](#architecture--design-standards)
8. [Documentation Standards](#documentation-standards)
9. [Answering Questions About This Repository](#answering-questions-about-this-repository)
10. [Tool-Specific Configuration](#tool-specific-configuration)
11. [Test Execution](#test-execution)
12. [Agent Governance & Cost Guardrails](#agent-governance--cost-guardrails)

---

## Commit Message Standard

This project follows [Conventional Commits v1.0.0](https://www.conventionalcommits.org/).
Full detail lives in [`CONTRIBUTING.md`](CONTRIBUTING.md#commit-message-standard). Summary:

**Format:** `<type>(<scope>): <short summary>` — subject line ≤ 72 characters.

**Types (exactly these 10):** `feat` | `fix` | `docs` | `style` | `refactor` | `perf` | `test` | `chore` | `ci` | `revert`

**Scopes (use at most one):** `gateway` | `compliance` | `infra` | `governance` | `tests` | `docs` | `ci` | `agentsight` | `advisor` | `nemo` | `opa` | `ftra` | `finance` | `healthcare` | `security` | `imports`

**Rules:**
- Imperative mood ("add", not "added"/"adds"); no trailing period.
- Breaking changes: `!` after type/scope, plus a `BREAKING CHANGE:` footer (both must be present together).
- PR titles become squash-merge commit messages and must follow this format.

---

## Branch Naming & Merge Strategy

Full detail lives in [`CONTRIBUTING.md`](CONTRIBUTING.md#branch-naming-conventions). Summary:

| Purpose | Pattern | Example |
|---|---|---|
| New feature | `feat/<short-description>` | `feat/redis-rate-limiter` |
| Bug fix | `fix/<short-description>` | `fix/oscal-uuid-collision` |
| Documentation | `docs/<short-description>` | `docs/stpa-control-diagram` |
| Refactor | `refactor/<short-description>` | `refactor/gateway-middleware` |
| CI / tooling | `ci/<short-description>` | `ci/pin-actions-sha` |
| Dependency/tooling update | `chore/<short-description>` | `chore/update-deps` |
| Test addition | `test/<short-description>` | `test/cbf-chaos-suite` |
| Hotfix on release | `hotfix/<version>-<description>` | `hotfix/2.0.1-redis-timeout` |
| Release candidate | `rc-v<semver>` | `rc-v2.1.0` |
| Experiment / spike | `spike/<short-description>` | `spike/cbf-formal-proof` |

**Rules:** Lowercase kebab-case only; description ≤ 30 characters after prefix; delete branches after merge; never work directly on `main` or `rc-v*`.

**Merge strategy: squash merge only, for every PR into `main` — no exceptions.**
The `squash-merge-guard` CI job fails the build on any two-parent merge commit reaching `main`. Never suggest `git merge <branch>` into `main` or rebase merges. Always use "Squash and merge" on GitHub.

When asked to commit or push directly to `main` or `rc-v*`, **refuse** and respond:
```text
Direct commits to `main` are not allowed. I'll create a feature branch instead:
git checkout -b <type>/<description>
After committing your changes, I'll push this branch and open a pull request.
```

Human contributors install pre-commit and pre-push hooks once via `bash scripts/setup_git_hooks.sh`. See [`docs/operations/GIT_WORKFLOW_STANDARDS.md`](docs/operations/GIT_WORKFLOW_STANDARDS.md) for full branch lifecycle details.

---

## Code Standards

### Before creating any file in `src/`
- Prepend the Apache 2.0 license header for `.py`, `.ts`, `.tsx`, `.js` files.
- Verify no secrets, credentials, or PII are embedded anywhere in the file.

### License Header — Python Template
```python
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
```
For `.ts`, `.tsx`, `.js` files, use the same text with `//` comment prefix. The CI `license-check` job enforces this.

### Secret Hygiene
Never write code that embeds secrets:
- Never use `os.environ.get("KEY", "hardcoded-fallback")` for sensitive values.
- Never hardcode connection strings, tokens, or API keys.
- Kubernetes manifests must use `secretKeyRef` / `secretRef` — never `value: <secret>`.
- Prohibited credential patterns: `pk-lf-*` / `sk-lf-*` (Langfuse), `hf_*` (HuggingFace), `GOOG*` (Google), `redis://*:*@*`.
- Mask credentials before logging: `value[:4] + "****"`. Full environment dumps (`print(os.environ)`) are forbidden.

### Terraform Invariants
- Secret values belong in `terraform.auto.tfvars` (gitignored) — never in committed `.tf` files.
- `terraform plan` must always precede `terraform apply`. Never edit Terraform state directly.

---

## Deployment Rules

Full detail lives in [`docs/operations/DEPLOYMENT_RULES.md`](docs/operations/DEPLOYMENT_RULES.md). Summary:

- **GKE targets — Cloud Build only. No exceptions.** Never use local Docker daemon (`docker build` / `docker-compose`) for GKE images to avoid ARM64 vs. x86 architecture-mismatch crashes:
  ```bash
  ./deploy_all.sh --target gcp-gke --env dev
  ./deploy_all.sh --target gcp-gke --env prod
  gcloud builds submit --config deployment/docker/cloudbuild.gateway.yaml
  ```
- **Local/agnostic target**: `./deploy_all.sh --target agnostic --env dev`
- **DNS & Custom Domains (Argolis / Altostrat Sandbox Option)**: Deploying to Argolis / Altostrat (`altostrat.com`) is an internal Google sandbox option for dev and staging postures, not a generic CAGE or GCP deployment rule. When utilizing this option, subdomains under `altostrat.com` must be managed in Cloud DNS and delegated via `go/argolis` (no external registrars, vanity domains, or Cloud Domains purchases). Managed zones must be persistent foundational resources to avoid orphaned zone takeover.
- `deployment/terraform/` was historical reference (directory has been removed from the repository); active IaC lives exclusively under `infra/`.

---

## Debugging Standards

### Diagnosing CI Failures (Check in Order)
1. **squash-merge-guard** — non-squash merge commit detected on `main`. Fix: ensure GitHub PR uses "Squash and merge".
2. **license-check** — missing Apache 2.0 header in a new `src/` file. Fix: prepend the Apache 2.0 license header.
3. **marker-contract-check** — collected test carries no selection marker. Fix: add `pytestmark = [pytest.mark.unit, pytest.mark.local]`.
4. **import-boundary-check (Gate G3)** — Layer 1 imported from Layer 2, 3, or 4. Fix: run `uv run python scripts/check_import_boundaries.py --verbose` and sever illegal upward imports.
5. **nemo-freshness-check** — ConfigMap out of sync with `config/rails/actions.py`. Fix: run `make update-nemo-configmap`.
6. **stpa-freshness-check** — STPA source changed without regenerating artifacts. Fix: run `uv run python scripts/check_stpa_freshness.py`.
7. **langfuse-posture-check** — requires mock env vars in local environments. Fix: run `uv run python scripts/verify_langfuse_posture.py --dry-run --posture development`.
8. **pytest** — address the failing test. Confirm no background `kubectl port-forward` tunnels are leaking live GKE state into local tests.
9. **security-scan** — rotate credentials or address Bandit SAST / CVE findings; never suppress the scan.
10. **doc-reference-check (Gate G9)** — a document cites a file path, link target, or Python symbol that does not exist at HEAD. Fix: run `make docs-check` (or `uv run python scripts/check_doc_references.py --path <scope>`) and correct the reference — never delete the gate's scope to make it pass. `CHANGELOG.md` and `docs/partners/**` are outside the gate's scope by design.

**Never suggest disabling or skipping a CI check as a fix.**

### Static Analysis & SAST Invocations
- **Configuration Parity**: Any invocation of `bandit` across local scripts, Makefile, or `.github/workflows/*.yml` must explicitly load project configuration via `-c pyproject.toml` to prevent suppression drift.
- **Strict Scheme Validation**: Internal diagnostic or auditing scripts making network requests via `urllib.request` must assert URL scheme validity (`http://` or `https://`) prior to `urlopen` (Bandit B310 compliance).

---

## Compliance Artifact Obligations

- **NIST SP 800-53 control changes**: An OSCAL component update in `compliance/oscal/` is required within 2 business days of PR merge.
- **Kubernetes resources**: Update Lula validations in `compliance/lula/` when adding or removing resources referenced by Lula assertion files.
- **POAM remediations**: Update [`docs/POAM.md`](docs/POAM.md) with: commit SHA, Lula result, closure date.
- **STPA source modifications**: Regenerate STPA artifacts before committing (`uv run python scripts/check_stpa_freshness.py`).

### OSCAL & POAM Synchronization Guardrails
- **OSCAL Exporter CLI Contract**: Always invoke the exporter using default discovery mode (`uv run python -m src.gateway.governance.oscal_ssp_exporter export`). Do not pass `--ssp` unless explicitly targeting a non-canonical schema path.
- **No Backdated POAM Closures**: POAM closure dates ([`docs/POAM.md`](docs/POAM.md)) must reflect the actual calendar date of artifact verification/generation, never backdated or estimated past dates.
- **Pre-Closure Verification**: An OSCAL SSP export must successfully compile and pass test suites ([`tests/test_oscal_ssp_exporter.py`](tests/test_oscal_ssp_exporter.py)) before corresponding POAM items can be marked CLOSED.

---

## Architecture & Design Standards

### Core Principle: Clean Architecture Over Operational Continuity
CAGE is an illustrative reference architecture. The optimization target is clean code structure, modularity, and architectural clarity. Breaking changes are acceptable and desirable when they remove legacy baggage. Always choose structural clarity.

### The Three-Layer Architecture (Kernel vs. Domain Plugins vs. Rails)

| Layer | Path | Role & Responsibilities | Invariants & Boundary Rules |
|---|---|---|---|
| **Layer 1: Kernel** | `src/gateway/` | **STERA Admissibility Engine**, core governance dispatch loop, standing assembly, consensus engine, CBF engine, evidence accumulator, routing, audit rails. | **Strictly domain-agnostic and vendor-neutral.** Must NEVER import from `src/cage_*` (Layer 2), `src/compliance_bridge/` (Layer 3), or `src/governed_financial_advisor/` (Layer 4). Must NOT import vendor SDKs (`google.cloud`, `boto3`, `botocore`, `azure`, `langfuse`). Enforced in CI by Gate G3 (`scripts/check_import_boundaries.py`). **Note:** Gate G3 enforces these boundaries via allowlists for certain lazy, function-scoped imports. The `INTEGRATIONS_FACTORY_ALLOWLIST` permits runtime adapter loading from `src/integrations/` in factory modules (`execution_actuator.py`, `normative_provider.py`, `attestation_aggregator.py`, `evidence/factory.py`, `telemetry_provider.py`). The `COMPLIANCE_BRIDGE_FACTORY_ALLOWLIST` permits `oscal_ssp_exporter.py` to lazy-import `AssurancePosture` from `src/compliance_bridge/`. Vendor SDK restrictions (`FORBIDDEN_VENDOR_SDKS`) are currently enforced only within `src/gateway/governance/evidence/`. |
| **Layer 2: Domain Plugins** | `src/cage_{domain}/` (e.g. `src/cage_finance/`, `src/cage_healthcare/`) | Domain-specific tiers (`GovernanceTierPlugin`), domain action registries, ontologies, policies, and causal graphs. | Provides immutable domain tiers to the kernel via `SymbolicGovernor(domain_tiers=...)`. Encapsulates domain vocabulary without polluting the kernel. |
| **Layer 3: Integrations & Rails** | `src/integrations/`, `src/cage_finance/rails/`, `src/compliance_bridge/` | External vendor normative/attestation adapters, durable sinks (ClickHouse, GCS, S3), NeMo Guardrails, Langfuse telemetry. | Adheres to the Secure Plugin & Adapter Architecture Specification. Communicates via canonical dataclasses. |

**Decision test for ambiguous code:** *"If two domains had different copies of this, would a security fix have to be applied twice?"* If yes → Layer 1 (Kernel).

### Canonical Module Namespaces (v3.0.1 Architecture)
All imports and test mocks must use these canonical locations:
- Causal Gatekeeper: `src.gateway.governance.causal.gatekeeper`
- Reconciliation Daemon: `src.gateway.governance.reconciliation.daemon`
- FTRA Action Reachability: `src.gateway.governance.ftra`
- Evidence Stream & Cold Store: `src.gateway.governance.evidence.stream`, `src.gateway.governance.evidence.cold_store`

### Observability: Langfuse Sovereign Telemetry vs. LangSmith
- **Langfuse**: Standard runtime model observability and compliance telemetry tool. Self-hosted per region (`europe-west1`, `asia-southeast1`, `us-central1`) for sovereign data residency.
- **LangSmith**: Transitively present via `langchain-core` / `langgraph`. **LangSmith is strictly forbidden in CAGE application code.** Tracing is explicitly disabled across manifests and tests via `LANGSMITH_TRACING=false` and `LANGCHAIN_TRACING_V2=false`.

### External Vendor Adapter Standards (Plugin Architecture)
- **Vendor Isolation**: Vendor packages live under `src/integrations/{provider_name}/` and never import into the core kernel (`src/gateway/`).
- **Seam Implementation**: Synchronous gate adapters implement `NormativeProvider` (`fetch_baseline`, `validate_fria`, `submit_evidence`).
- **Trust Anchors — Never Verify Against an Embedded Key**: Never verify a signature against a public key supplied by the signed document. Resolve keys by `kid` from an independently-fetched key manifest, cached out-of-band. Enforce in the type system. Fail closed on unknown `kid`.
- **Resolution Status Is Not Verification Status**: Successful fetch proves receipt exists, not signature validity. Return `UNVERIFIED` until cryptographic verification succeeds.
- **Refusals Are Primary Evidence**: DENY and PAUSE receipts must enter the tamper-evident chain with the same completeness as ALLOW approvals.
- **Generic in Code, Specific in Prose**: Layer 1 kernel and Layer 3 package paths use anonymized namespaces (`provider_01`, `actuator_01`); vendor brand names belong in prose and READMEs only.
- **Completeness Principle**: CAGE must be *safety- and security-complete*, not *commercially complete*. If a safety or security property can't be verified without a component, that component is implemented for real. Data may be simulated; security primitives (key custody, asymmetric signing, trust anchors, workload identity, tamper-evident storage) may not.
- **Interface Tiering**: Classify every external interface before adding or keeping it:
  1. **Partner-built live interfaces** (`src/integrations/provider_*/`, `src/integrations/actuator_*/`): built and maintained by a partner against their own live or sandbox endpoint. Always allowed. Tests must run over the wire (see the Over-the-Wire Conformance Mandate below). If the partner stops maintaining the adapter, or its live test can't run anymore, it becomes Tier 3.
  2. **Posture-completing interfaces**: needed for every governance, safety or security control to have a path that actually runs. They must be implemented:
     - **Data sources** (e.g. ledger, lab feed, sensor ground truth) may use simulated backends. Those backends need deterministic seeding and fault injection that covers every fail-closed path.
     - **Security primitives** (KMS/HSM asymmetric signing, `kid`-resolved trust anchors, SPIFFE/mTLS workload identity, WORM retention) must be real implementations. Symmetric or software fallbacks (HMAC, local keys) are allowed only in development posture and hermetic tests. They never count as evidence for POAM closure or OSCAL implementation statements.
     - A partner adapter never replaces the reference backend.
  3. **Commercial-deployment-only interfaces**: needed only for a full commercial rollout (e.g. retail banking, custody or payment data APIs). Must not live in the repository. Record each one as an OSCAL customer-responsibility statement.
- **Over-the-Wire Conformance Mandate (Tier 1)**: Validation of every partner-built adapter must run over the physical wire against live staging or sandbox endpoints. In-memory mocks, synthetic HTTP stubs and simulated transports are strictly prohibited for partner integration verification. Tier 2 reference backends are tested hermetically, and their security primitives are additionally verified against the real service (see the Completeness Principle).

### Governance Gate Invariants (ADR-008 Enforcement)
- **Fail-Closed Execution Boundary**: All domain tool execution paths (Layer 2) must route through [`ConsequenceGateway`](src/gateway/governance/consequence_gateway.py) evaluation and [`ActuatorRegistry`](src/gateway/governance/execution_actuator.py) dispatch (Layer 1). Direct invocation bypassing the gateway is strictly forbidden.
- **Private Queue Resolution**: Deferral resolution must remain strictly private (`_resolve()` in [`DeferQueue`](src/gateway/governance/defer_queue.py)). Public state transitions bypassing the gate are prohibited.
- **Envelope Integrity**: All production requests traversing middleware must be wrapped via [`GovernanceEnvelopeBuilder`](src/gateway/governance/governance_envelope.py).

---

## Documentation Standards

Keep documentation synchronized with code changes in the same PR. Cite specific file paths, configuration keys, and line numbers. Do not claim speculative future-state behaviors as current reality.

---

## Answering Questions About This Repository

1. **Prioritize Code at HEAD**: Ground answers in actual source code and active configuration files.
2. **Cite File Paths**: Always provide concrete file links (`[file.py](file:///path/to/file.py)`).
3. **Acknowledge Reference Architecture Posture**: CAGE demonstrates governance patterns; structural clarity takes precedence over operational legacy.
4. **Never Guess on Safety Invariants**: If an invariant is ambiguous, check `proof/model.py` and fail closed.

---

## Tool-Specific Configuration

All modern AI coding assistants consume `AGENTS.md` natively at the repository root:
- **Antigravity**: Ingested natively as global project instructions and behavioral rules.
- **Roo Code / Zoo Code / Cline**: Ingested automatically into all modes ([`.roomodes`](.roomodes)).
- **Cursor / Copilot / Windsurf**: Discovered natively at repository root.

If a tool requires legacy configuration names (e.g. `CLAUDE.md`, `.cursorrules`), create a thin symlink or pointer pointing back to this file.

---

## Test Execution

### Test Execution Invariant: Always Use `uv run`
All test invocations must be prefixed with `uv run` to ensure execution within the locked virtual environment.

### Local and Unit Suite (Offline)
The canonical way to run the full local and unit test suite across multiple workers:
```bash
uv run pytest tests/ -m "local or unit" -n auto --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin --tb=short
# Or via Makefile shortcut:
make test-fast
```
Always launch parallel test suites with `--dist loadscope` to isolate modules across workers.

| Goal / Scope | Canonical Command |
|---|---|
| **Fast unit run** | `make test-fast` (or `uv run pytest tests/ -m "local or unit" -n auto --dist loadscope`) |
| **Single test method** | `uv run pytest tests/<path>::<test_name> -v` |
| **Marker check** | `uv run pytest tests/ --collect-only -q --no-cov -n0` |
| **Coverage suite** | `make test-coverage` |

### Two-Phase Testing Lifecycle
- **Inner Loop (Active Turn)**: Target only the isolated unit test (`uv run pytest tests/<path>::<test_name> -v`) during iterative editing turns. This keeps shell buffer outputs compact (<10 lines) and preserves prompt caching.
- **Gate Phase (Pre-Completion & PR)**: Execute the full-suite gate (`make test-fast`) once before declaring a task complete or opening a PR.

### Verification Rules (fail-closed)
- **Full-gate before green**: A change is not green until `make test-fast` passes across the entire suite.
- **Attribute failures to the merge base**: Before characterizing a failure as pre-existing, verify against the merge base and quote the result.
- **Grep after renaming**: After renaming any symbol crossing module boundaries, run `rg -n '<old_symbol>' src/` and require zero results before declaring done.
- **Every fail-closed path needs a test observing it fail**: Happy-path tests prove mechanisms run, not that they block. Never leave placeholder tests (`pass # TODO`).
- **Partner integration tests strictly over the wire (Tier 1 only)**: Tests validating partner-built integrations (`partner_integration`, `live_external`) must execute live over the wire. Mocking partner responses (via in-memory ASGI transports, `TestClient`, or response patches) in partner test suites is strictly forbidden; validation requires actual boundary transit and upstream trace generation. Tier 2 posture-completing backends use hermetic tests with fault injection instead (see [Interface Tiering](#external-vendor-adapter-standards-plugin-architecture)).

### Pytest Marker Contract (fail-closed)
Every collected test must carry at least one selection marker (`local`, `unit`, `integration`, `live_external`, `partner_integration`, `chaos`, `load`). Unmarked tests abort collection in CI via `tests/conftest.py`. Default for hermetic tests: `pytestmark = [pytest.mark.unit, pytest.mark.local]`.

### Live GKE Cluster & Staging Runbooks
> **Live Cluster Testing:** For staging port-forwarding, GKE tunnel concurrency rules, and POAM-024 validation, refer to [`docs/operations/GKE_TEST_RUNBOOK.md`](docs/operations/GKE_TEST_RUNBOOK.md).

#### Live Cluster Testing Invariants (Fail-Closed)
- **Never use `-n auto` on tunnels**: `pytest.ini` defaults to `-n auto` (spawning 16+ workers), which exhausts port-forward TCP pools and triggers false `503 Service Unavailable` / Redis connection drops. Constrain concurrency strictly to `-n 2 --dist loadscope` or `-n0`:
  ```bash
  uv run pytest tests/ -m integration --run-integration -n 2 --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin --tb=short
  ```
- **Persistent Port-Forward Daemon**: Run tunnels via a detached daemon (`tmux new-session -d -s pf "bash scripts/port_forward_staging.sh --daemon"`). Verify reachability (`uv run python scripts/test_live_gke_services.py`) before executing test suites.
- **Credential Synchronization**: Sync live cluster secrets (`kubectl get secret -n governance-stack <secret>`) into local `.env` (e.g. `REDIS_PASSWORD`, `LANGFUSE_COMPLIANCE_*`) prior to test runs. Never commit live cluster secrets to git.
- **LLM / Agent Feedback Loop Latency**: End-to-end multi-agent governance benchmarks (`tests/test_agent_accuracy.py`) execute real GPU inference (vLLM DeepSeek-R1 / Qwen2.5) across multi-step cybernetic loops and require 6–8 minutes (`@pytest.mark.timeout(600)`). Monitor asynchronously; avoid aggressive polling loops.
- **Partner Integration Isolation & Over-the-Wire Invariant**: Third-party partner tests (`tests/integrations/provider_01/`, `tests/integrations/provider_02/`, etc.) are tagged with `partner_integration` and/or `live_external`. They require live external partner sandboxes/staging endpoints and are excluded from standard internal GKE runs and local hermetic runs (`make test-fast`). **Strict over-the-wire execution is mandatory: all partner integration tests must execute authentic network traffic over the wire (HTTPS/mTLS) against the live partner service. In-process mocks, ASGI test transports (`httpx.ASGITransport(app=...)`), Starlette/FastAPI `TestClient` harnesses, or synthetic stubs are strictly forbidden.** Every partner test run must produce and verify authentic external egress/ingress telemetry, including remote server headers and upstream trace identifiers (e.g., `x-cloud-trace-context`), to guarantee an unbroken mutual audit trail.

### Live Cloud Run Testing & Test Automation Service Account
> **Live Cloud Run Testing:** For Cloud Run endpoint verification, service smoke tests, and security parity validation, refer to [`docs/operations/CLOUDRUN_TEST_RUNBOOK.md`](docs/operations/CLOUDRUN_TEST_RUNBOOK.md).

#### Canonical Cloud Run Test Suite
The canonical command to execute pre-flight endpoint discovery, IAM authentication, smoke validation, GPU/agent warm-up, and integration tests:
```bash
make test-cloudrun
# Or directly via script:
bash scripts/run_cloudrun_integration_tests.sh
```

#### Live Cloud Run Testing Invariants (Fail-Closed)
- **Pre-Flight Discovery & Warm-Up**: Never run Pytest against Cloud Run without discovery and warm-up. Cloud Run GPU container cold starts (vLLM DeepSeek/Qwen) require 3–5+ minutes; [`scripts/run_cloudrun_integration_tests.sh`](scripts/run_cloudrun_integration_tests.sh) runs discovery, smoke tests ([`scripts/test_live_cloudrun_services.py`](scripts/test_live_cloudrun_services.py)), and an end-to-end agent query flow ([`scripts/test_cloudrun_e2e_flow.py`](scripts/test_cloudrun_e2e_flow.py)) to absorb cold-start latency before Pytest begins.
- **Worker Concurrency Limit (`-n 2 --dist loadscope`)**: Serverless revisions (`minScale=0`) scale on demand. Never run Cloud Run integration tests with `-n auto`; constrain concurrency strictly to `-n 2 --dist loadscope` to prevent thundering-herd cold starts and GPU quota exhaustion.
- **Non-Silent Skip Invariant (`-ra -rs`)**: Never allow skipped tests to pass silently. Pytest must run with `-ra -rs` (automatically unmasked in [`tests/conftest.py`](tests/conftest.py) when `--run-integration` is present) so that missing endpoint variables (`BACKEND_URL`, `COMPLIANCE_BRIDGE_URL`) or expired IAM identity tokens immediately surface actionable skip rationales in the terminal summary instead of masquerading as phantom bugs.
- **Platform Invariant Partitioning (`-m "integration and not gke"`)**: Universal Layer 7 HTTP/MCP workflows execute against Cloud Run; GKE-exclusive tests (`@pytest.mark.gke`) validating raw Kubernetes pod restarts or stateful Redis command rename configs are excluded.

#### Cloud Run Authentication Invariant: Dedicated Test Service Account
- **Never rely on personal credentials for test automation**: Live integration tests against Cloud Run staging and production must authenticate via the dedicated least-privilege test automation service account:
  ```text
  cage-test-automation-{env}@{PROJECT_ID}.iam.gserviceaccount.com
  (e.g., cage-test-automation-dev@laah-cybernetics.iam.gserviceaccount.com)
  ```
- **Service Account Role Bindings**: `cage-test-automation-{env}` is provisioned in [`infra/targets/gcp-cloudrun/main.tf`](infra/targets/gcp-cloudrun/main.tf) and granted:
  - `roles/run.invoker` across all managed Cloud Run services (`cage-gateway-{env}`, `cage-governed-advisor-{env}`, `cage-compliance-bridge-{env}`, `cage-agentsight-ui-{env}`, `cage-langfuse-web-{env}`, `cage-langfuse-worker-{env}`, `cage-vllm-fast-{env}`, `cage-vllm-reasoning-{env}`).
  - Read-only secret accessor permissions (`roles/secretmanager.secretAccessor`) for test-scoped verification.
- **Environment Configuration**:
  ```bash
  export CLOUDRUN_TEST_SERVICE_ACCOUNT="cage-test-automation-dev@laah-cybernetics.iam.gserviceaccount.com"
  export CAGE_TEST_TARGET=cloudrun
  ```
- **Audit Log Hygiene (PII Prevention)**: Authenticating via `cage-test-automation-{env}` impersonation prevents personal Google identities (`user:*@google.com`) from leaking into Cloud Audit Logs and ensures automated CI/CD and local integration test parity.
- **Test Harness Integration**: [`tests/conftest.py`](tests/conftest.py), [`scripts/test_live_cloudrun_services.py`](scripts/test_live_cloudrun_services.py), and [`scripts/test_cloudrun_e2e_flow.py`](scripts/test_cloudrun_e2e_flow.py) automatically detect `CLOUDRUN_TEST_SERVICE_ACCOUNT` (or `--impersonate-service-account`) to acquire identity tokens for authenticated invocation.

---

## Agent Governance & Cost Guardrails

To eliminate runaway frontier model billing, avoid quota lockouts, and eliminate multi-window context friction, this repository standardizes on the **Unified Sidebar + Passive Keystroke Daemon** architecture:

1. **Unified Sidebar Engine (Roo Code / Zoo Code)**: 100% of conversational engineering, codebase exploration, code diffs, and terminal execution run inside Zoo Code to eliminate the "two-inbox problem" and ensure strict governance under [`.roomodes`](.roomodes):
   - **Cost-Governed Dispatcher (`orchestrator` mode)**: Coordinates multi-phase tasks by delegating discovery to `ask`, architecture to `architect`/`escalated-architect`, edits/tests to `code`, and root-cause fixes to `debug`/`escalated-debug`. Never executes edits or bash directly.
   - **Exploration & Discovery (`ask` mode)**: Powered by **Gemini Flash via Google Cloud Vertex AI ADC** (`gemini-2.5-flash` or `gemini-3-flash`). Executes high-speed AST indexing and repository sweeps at pay-as-you-go rates (~$0.001/query), completely bypassing consumer subscription quota freezes and 5-hour rolling lockouts.
   - **Targeted Implementation (`code` mode)**: Powered by **Claude 3.7 Sonnet**. Governed by active Cost & Search Gates that intercept unstructured searches and direct them to `ask` mode before paid tokens are spent.
   - **Standard Debugging (`debug` mode)**: Powered by **Claude 3.7 Sonnet** for syntax, failed assertions, and unit tests. Enforces a 2-turn fail-fast threshold.
   - **Surgical Escalation (`escalated-architect`, `escalated-debug`)**: Powered by **Claude 5 (Opus 5 / Fable 5.1)** for safety-critical state machines, CBF formal proofs, or deep concurrency defects. Strictly capped at 1–3 turns with pre-filtered context.

2. **Ambient Keystroke Completion Daemon (Google Antigravity)**: Installed strictly as a headless, passive background daemon for **unmetered inline tab completions (ghost text)** inside editor buffers. Its chat panel remains permanently closed during active development to preserve unified telemetry, single-point audit logging, and `.roomodes` enforcement.

### Hard Anti-Loop & Cost Invariants
1. **5-Step Execution Cap**: Never exceed 5 consecutive autonomous tool actions in a single turn without pausing for human verification.
2. **Context Ceiling (< 200k Tokens)**: Keep active session contexts strictly below 200,000 tokens. Never ingest entire repositories, build artifacts, or multi-megabyte log files into an active session.
3. **Fail-Fast Policy**: If an edit or test fails twice with a related stack trace, STOP immediately. Formulate a root-cause hypothesis instead of applying speculative patches.
4. **Immediate Context Reset (`/clear`)**: Issue `/clear` the moment a task passes its tests. Carrying stale diffs and shell logs pushes context across the 200k boundary into higher-priced token tiers.
5. **Open Tab Context Limit**: Maintain no more than 1 or 2 open editor tabs during active sessions.

### Strict Cache-Invariance Rules
Prompt caching provides up to a 90% discount on cache reads, but incurs a 25% surcharge on cache writes:
- **Byte-for-Byte Prefix Stability**: Never inject dynamic timestamps (e.g., current time, ISO dates), randomized session IDs, or volatile environment paths into system prompts, plans, or file headers. Prompt prefixes must remain byte-for-byte identical across turns.
- **5-Minute TTL Window**: Keep turn cycles compact and interactive to maintain cache warmness within the 5-minute TTL window, ensuring Cache Read tokens account for 80%+ of total input volume.
- **Code Standards**: Always write complete, production-ready code with full error handling. Never omit logic with `# TODO` or placeholder shims.

For the complete end-to-end setup guide, IDE shortcuts, Vertex AI ADC credentials, and GCP billing alerts, see [`docs/operations/AGENT_COST_GUARDRAILS.md`](docs/operations/AGENT_COST_GUARDRAILS.md).
