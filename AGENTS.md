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

---

## Commit Message Standard

This project follows [Conventional Commits v1.0.0](https://www.conventionalcommits.org/).
Full detail (examples, self-validation checklist) lives in
[`CONTRIBUTING.md`](CONTRIBUTING.md#commit-message-standard). Summary:

**Format:** `<type>(<scope>): <short summary>` — subject line ≤ 72 characters.

**Types (exactly these 10):** `feat` | `fix` | `docs` | `style` | `refactor` |
`perf` | `test` | `chore` | `ci` | `revert`

**Scopes (use at most one):** `gateway` | `compliance` | `infra` | `governance` |
`tests` | `docs` | `ci` | `agentsight` | `advisor` | `nemo` | `opa` | `ftra` |
`finance` | `healthcare` | `security` | `imports`

**Rules:**
- Imperative mood ("add", not "added"/"adds")
- No trailing period
- Breaking changes: `!` after type/scope, plus a `BREAKING CHANGE:` footer
  (both must be present together, never just one)
- PR titles become squash-merge commit messages and must also follow this
  format

Before finalizing any commit message or PR title, self-check: type is valid,
scope (if present) is valid, subject ≤ 72 chars, imperative mood, no trailing
period, and breaking-change marker/footer are coupled correctly.

---

## Branch Naming & Merge Strategy

Full detail lives in [`CONTRIBUTING.md`](CONTRIBUTING.md#branch-naming-conventions).
Summary:

| Purpose | Pattern | Example |
|---|---|---|
| New feature | `feat/<short-description>` | `feat/redis-rate-limiter` |
| Bug fix | `fix/<short-description>` | `fix/oscal-uuid-collision` |
| Documentation | `docs/<short-description>` | `docs/stpa-control-diagram` |
| Refactor | `refactor/<short-description>` | `refactor/gateway-middleware` |
| CI / tooling | `ci/<short-description>` | `ci/pin-actions-sha` |
| Hotfix on release | `hotfix/<version>-<description>` | `hotfix/2.0.1-redis-timeout` |
| Release candidate | `rc-v<semver>` | `rc-v2.1.0` |
| Experiment / spike | `spike/<short-description>` | `spike/cbf-formal-proof` |

**Rules:** lowercase kebab-case only; description ≤ 30 characters after the
prefix; delete branches after merge; never work directly on `main` or `rc-v*`.

**Merge strategy: squash merge only, for every PR into `main` — no exceptions,
including release integration branches.** A `squash-merge-guard` CI job
(`.github/workflows/ci.yml`) fails the build on any two-parent merge commit
reaching `main`. Never suggest `git merge <branch>` into `main`, `git merge
--no-ff`, or GitHub's "Create a merge commit" / "Rebase and merge" options.
Always say: *"Use 'Squash and merge' on GitHub; confirm the pre-filled commit
message matches the PR title and follows Conventional Commits format."*

When asked to commit or push directly to `main` or `rc-v*`, refuse and instead
suggest a feature branch + PR.

---

## Code Standards

### Before creating any file in `src/`
- Prepend the Apache 2.0 license header for `.py`, `.ts`, `.tsx`, `.js` files
  (template below).
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

For `.ts`, `.tsx`, `.js` files, use the same text with `//` comment prefix.
The CI `license-check` job enforces this on every PR.

### Secret Hygiene

Never write code that embeds secrets:
- Never use `os.environ.get("KEY", "hardcoded-fallback")` for sensitive values.
- Never hardcode connection strings, tokens, or API keys.
- Kubernetes manifests must use `secretKeyRef` / `secretRef` — never `value: <secret>`.

Credential patterns that must never appear in committed files:
`pk-lf-*` / `sk-lf-*` (Langfuse), `hf_*` (HuggingFace), `GOOG*` (Google), `redis://*:*@*`.

When adding diagnostic logging or tracing, never log secrets/tokens/PII, never
dump the full environment, and mask any credential-shaped value before logging
(`value[:4] + "****"`).

### Before suggesting any Terraform change
- Secret values belong in `terraform.auto.tfvars` (gitignored) — never in
  committed `.tf` files.
- `terraform plan` must always precede `terraform apply`.
- Never edit Terraform state directly.

### Test Execution: Always Use `uv run`

This project is managed with [`uv`](https://docs.astral.sh/uv/) (see `uv.lock`
and `pyproject.toml`). All test and verification invocations must be prefixed with `uv run`.
Never invoke `pytest`, `python`, or `python -m pytest` directly without the `uv run`
prefix — doing so bypasses the project's locked, reproducible virtual environment.

When running tests in parallel with `pytest-xdist` (`-n auto`), launch the test suite
with `--dist loadscope` (or `--dist=loadfile`) to preserve module/class fixture and event loop
reuse and prevent cross-worker fixture churn.

**Test Performance & Fast Local Iteration Rules:**
1. **Parallel Worker Distribution**: Use `-n auto --dist loadscope` to group module/class tests on the same worker process.
2. **Disable Coverage Locally**: Do not run `--cov` during fast development cycles — `pytest-cov` / `sys.settrace` adds 30% to 100% overhead. Pass `--no-cov` (or use `make test-fast`) and reserve `--cov` for pre-merge validation (`make test-coverage`) or CI.
3. **Disable Heavy Telemetry Plugins (LangSmith / Tracing)**: CAGE uses Langfuse for sovereign compliance telemetry; LangSmith is never used by CAGE application code, but is pulled in transitively by `langchain-core` / `langgraph`. Prevent LangSmith's Pytest entrypoint hook from loading by passing `-p no:langsmith_plugin -p no:langsmith` and setting `LANGCHAIN_TRACING_V2=false` and `LANGSMITH_TRACING=false`.
4. **Asyncio Loop Scoping**: `pytest-asyncio` is configured with `asyncio_default_fixture_loop_scope = module` and `asyncio_default_test_loop_scope = module` in `pytest.ini` to avoid per-test event loop teardown overhead.
5. **Slow Test Profiling**: Use `--durations=20 --durations-min=1.0` to diagnose slow tests and setup/teardown bottlenecks.

**Performance Optimization for High-Core Linux / VM Environments (e.g., `dev-thin-client`):**
To maximize throughput and avoid disk lock contention across parallel workers, point pytest's temporary directory to shared memory (`tmpfs`):
```bash
uv run pytest tests/ -m "local or unit" -n auto --dist=loadfile --tb=short --basetemp=/dev/shm/pytest
```

Correct:
```bash
uv run pytest
uv run pytest tests/ -m "local or unit" -n auto --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin --tb=short
uv run pytest tests/ -m "local or unit" -n auto --dist=loadfile --tb=short --basetemp=/dev/shm/pytest
uv run pytest tests/test_tls_enforcement.py -v
uv run pytest --cov=src --cov-report=term-missing
uv run python proof/model.py
make test-fast
```

Incorrect (do not suggest):
```bash
pytest
python -m pytest
pytest -n auto  # Missing --dist loadscope and uv run prefix
python proof/model.py
```

This applies to all agents, contributors, and CI documentation examples.

**Note for Autonomous Agents (Sandbox Execution):**
When running `uv run ...` as an AI agent inside a restricted terminal sandbox, the command may fail due to sandbox path boundaries (e.g. `zsh:1: operation not permitted: uv`, exit code 127) or socket connectivity resets (`connecting to sandbox server: read unix @->@: recvmsg: connection reset by peer`). When encountering this, do not switch to a different test runner like bare `python` or `pytest`; instead, configure the tool call to bypass the sandbox (e.g. `BypassSandbox: true`) so that the command executes natively in the host environment and accesses `uv`. When retrying with `BypassSandbox: true`, keep `toolAction` and `toolSummary` strictly identical.

**Hermetic Local Test Execution vs. Active Port-Forwards:**
When background port-forwards are running (such as those started via `scripts/port_forward_dev.sh`), localhost ports (Redis `6379`, OPA `8181`, Langfuse `3000`/`3001`, Gateway `8080`) are actively bridged to the live GKE development cluster. Local unit tests (`pytest tests/ -m "local or unit"`) that do not strictly isolate network sockets can inadvertently connect to the live GKE cluster and encounter live state (e.g., existing fence epochs, active cache keys), causing unexpected assertions like `assert cbf._last_seen_epoch == 42` reading live Redis epoch `17`.
- **Before running pure local/unit tests**: Verify no background tunnels are running (`ps aux | grep port-forward`), or terminate them if isolated offline execution is desired (`pkill -f "kubectl port-forward"`).
- **For integration testing against live GKE**: Launch `scripts/port_forward_dev.sh` and run with `tests/ --run-integration`.

---

## Deployment Rules

Full detail lives in [`docs/operations/DEPLOYMENT_RULES.md`](docs/operations/DEPLOYMENT_RULES.md).
Summary:

**GKE targets — Cloud Build only. No exceptions.** Never use the local Docker
daemon (`docker build`) for GKE-targeted images: building ARM64 images on a
developer laptop and running them on x86 GKE nodes causes architecture-mismatch
crashes.

```bash
# APPROVED for GKE
./deploy_all.sh --target gcp-gke --env dev
./deploy_all.sh --target gcp-gke --env prod
gcloud builds submit --config deployment/docker/cloudbuild_gateway.yaml

# APPROVED for local/agnostic
./deploy_all.sh --target agnostic --env dev
```

**Never suggest for GKE:**
- `docker build ... && docker push ...` or `docker-compose build && ... push`
- `--platform linux/amd64` local/BuildKit cross-compilation
- `kubectl apply` without a preceding Cloud Build step

**Cloud Build config files:** `deployment/docker/cloudbuild_gateway.yaml`
(gateway), `deployment/docker/cloudbuild.vllm.yaml` (vLLM),
`deployment/docker/cloudbuild.lula.yaml` (Lula).

Terraform state is in a GCS backend (`infra/targets/gcp-gke/backend.tf`).
Active IaC lives under `infra/`; `deployment/terraform/` is historical
reference only — never target it for new designs.

---

## Debugging Standards

### Secret & Credential Safety

When adding diagnostic logging, tracing, or debug output:
- Never log secrets, tokens, credentials, or PII — even temporarily.
- Never suggest `print(os.environ)` or equivalent full-environment dumps.
- Never suggest logging request headers wholesale without first filtering
  `Authorization`, `X-Api-Key`, `Cookie`, and similar sensitive headers.
- Mask any credential-shaped value before logging: `value[:4] + "****"`.

### Diagnosing CI Failures

Check these jobs in order:

1. **squash-merge-guard** — non-squash merge commit detected on `main`. Fix: ensure GitHub PR uses "Squash and merge" (never merge commits or rebase).
2. **license-check** — missing Apache 2.0 header in a new `src/` file. Fix: prepend the Apache 2.0 license header.
3. **import-boundary-check (Gate G3 in `lint`)** — Layer 1 (`src/gateway/`) imported from Layer 2 (`src/cage_*`) or Layer 4 (`src/governed_financial_advisor/`). Fix: run `uv run python scripts/check_import_boundaries.py --verbose` and sever illegal upward imports to maintain kernel/plugin isolation.
4. **nemo-freshness-check** — `deployment/k8s/nemo-rails-configmap.yaml` is out of sync with `config/rails/actions.py`. Fix: run `make update-nemo-configmap`.
5. **stpa-freshness-check** — STPA source changed without regenerating artifacts. Fix: run `scripts/check_stpa_freshness.py`.
6. **langfuse-posture-check** — requires mock cloud and Langfuse environment variables in local/offline environments. Fix: supply mock project/keys with derived `GOOGLE_CLOUD_LOCATION` and run `python scripts/verify_langfuse_posture.py --dry-run --posture development` (see [Langfuse Regional & Local Testing Limitations](#langfuse-regional--local-testing-limitations)).
7. **pytest** — address the failing test before suggesting any workaround. Always verify:
   - **No active port-forward contamination**: ensure `kubectl port-forward` to dev Redis (6379) / OPA (8181) is not polluting local test state.
   - **Canonical module paths**: verify imports use post-v3 locations (`src.gateway.governance.causal.gatekeeper`, `src.gateway.governance.reconciliation.worker`, `src.gateway.governance.safety.cbf_engine`).
   - **Governor contracts**: verify `SymbolicGovernor` instantiations provide `safety_filter`, `consensus_engine`, and context parameters.
8. **security-scan** — rotate the credential or address Bandit SAST / dependency CVE findings; never suggest suppressing the scan.

**Never suggest disabling or skipping a CI check as a fix.**

### Diagnosing Deployment / Terraform Failures

- Verify the deployment used Cloud Build, not local `docker build`.
- Check pod status: `kubectl get pods -n governance-stack`.
- Never suggest `terraform apply` without a preceding `terraform plan`.
- Never suggest editing Terraform state directly.

### Diagnosing Compliance Failures

- When a Lula validation fails, identify which assertion file failed
  (`lula-validation-*.yaml`) and distinguish universal gates (ISO 42001) from
  regional gates (US_FED / EU_ECB / APAC_MAS) — regional failures do not block
  the global stable tag.
- When OSCAL coverage is below threshold, run
  `src/gateway/governance/oscal_ssp_exporter.py` to regenerate the SSP.

---

## Compliance Artifact Obligations

When writing code that touches NIST SP 800-53 control implementations:
- An OSCAL component update in `compliance/oscal/` is required within 2
  business days of PR merge.

When adding or removing Kubernetes resources referenced by Lula validation files:
- Include a Lula validation update in `compliance/lula/` in the same PR, or
  flag it for a follow-on PR.

When remediating an open POAM finding:
- Update [`docs/POAM.md`](docs/POAM.md) with: commit SHA, Lula result, closure date.

When modifying STPA source files:
- Regenerate STPA artifacts before committing (`scripts/check_stpa_freshness.py`).

---

## Architecture & Design Standards

### Core Principle: Clean Architecture Over Operational Continuity & Backward Compatibility

CAGE is an illustrative **reference architecture**, not an active production service:
- **Optimization Target**: The primary design goal is **clean code structure, strict layer separation, and architectural legibility** — not operational safety, uptime, or backward compatibility.
- **Breaking Changes Are Desirable**: There is no live production instance to protect. Breaking changes are acceptable and often desirable when they eliminate legacy baggage, sever illegal coupling, or simplify the mental model. No deprecation window or migration shim is owed.
- **Operational Patterns Are Illustrative**: Infrastructure manifests, Cloud Build pipelines, and operational procedures describe reference patterns for adopters, not operational obligations that constrain maintainers or justify architectural compromises.
- **Decision Rule**: Whenever forced to choose between operational convenience/backwards compatibility and structural clarity, **always choose structural clarity**.

### Release Versioning

- Releases follow SemVer (`MAJOR.MINOR.PATCH`).
- Release branches: `rc-v<X.Y.Z>` branched from `main`; feature freeze applies
  immediately on branch creation.
- Stable tags are annotated: `git tag -a v<X.Y.Z> -m "release: v<X.Y.Z> — ..."`.
- Regional gates (US_FED, EU_ECB, APAC_MAS) are additive — they block regional
  deployment posture only, never the global stable tag.

### The Three-Layer Architecture (Kernel vs. Domain Plugins vs. Rails)

CAGE enforces strict separation between the universal governance kernel, domain-specific plugins, and external rails:

| Layer | Path | Role & Responsibilities | Invariants & Boundary Rules |
|---|---|---|---|
| **Layer 1: Kernel** | `src/gateway/` | Core governance dispatch loop, standing assembly, consensus engine, CBF engine, evidence accumulator, routing, and audit rails. | **Strictly domain-agnostic.** Must NEVER import from `src/cage_*` or `src/governed_financial_advisor/` (enforced by Gate G3 `scripts/check_import_boundaries.py`). Must not hardcode domain verbs (e.g. `execute_trade`) or domain data structures. |
| **Layer 2: Domain Plugins** | `src/cage_{domain}/` (e.g. `src/cage_finance/`, `src/cage_healthcare/`) | Domain-specific tiers (`GovernanceTierPlugin`), domain action registries, ontologies, policies, and causal graphs. | Registers tiers into the kernel via `SymbolicGovernor.register_tier()`. Encapsulates domain vocabulary and semantics without polluting the kernel. |
| **Layer 3: Integrations & Rails** | `src/integrations/`, `src/cage_finance/rails/` | External vendor normative/attestation adapters, NeMo Guardrails, Langfuse telemetry. | Adheres to the Secure Plugin & Adapter Architecture Specification. Communicates via canonical dataclasses. |

**The Three-Layer Split Rule:**
- **Layer 1 (Kernel)**: Code that can fail closed unsafely lives in the kernel. Code covered by TLA+ proofs, formal CBF math, or core NIST control assertions. Code that holds Redis Lua scripts, KMS envelope signing, or fence epoch tracking.
- **Layer 2 (Domain Plugin)**: Code that merely names domain concepts (actions, symbols, tickers, dosages), Rego domain packages, domain Pydantic models, or ledger providers.
- **Config**: Numbers, thresholds, citations, and STPA hazard declarations (`config/`).

**Decision test for ambiguous code:** *"If two domains had different copies of this, would a security fix have to be applied twice?"* If yes → Layer 1 (Kernel).

### FTRA (Tier 0.5 — Commencement-Time Reachability & Action Taxonomy)

Action reachability analysis and registry integrity controls live in `src/gateway/governance/ftra/`:
- **Action Taxonomy**: Actions are classified into canonical categories: `REVERSIBLE`, `IRREVERSIBLE`, and `EXTERNALLY_REVERSIBLE` (per OWASP AISVS C9).
- **Fail-Closed Boundary**: Any unknown or unclassified action must fail closed. Read-only actions bypass heavy barrier verification only when explicitly verified as read-only.
- **Registry Integrity**: Registries must be signed using KMS/JCS canonicalization, preventing untracked runtime capability escalation.

### Canonical Module Namespaces (v3.0.0 Architecture)

Refactoring across v3.0.0 extracted domain mechanisms into domain plugins and modularized gateway subpackages. All imports and test mocks must use these canonical locations:

| Component | Canonical Location | Deprecated / Relocated Path (Do Not Import) |
|---|---|---|
| Causal Gatekeeper | `src.gateway.governance.causal.gatekeeper` | `src.gateway.governance.causal_gatekeeper` |
| Reconciliation Worker | `src.gateway.governance.reconciliation.worker` | `src.cage_finance.compliance.reconciliation_worker` |
| CBF Engine | `src.gateway.governance.safety.cbf_engine` | `src.cage_finance.safety.cbf` |
| FTRA Package | `src.gateway.governance.ftra` | Legacy flat imports in root governance |
| Financial Tiers | `src.cage_finance.tiers` | Hardcoded blocks in `symbolic_governor.py` |
| Healthcare Tiers | `src.cage_healthcare.tiers` | N/A (new domain plugin) |

### Observability Architecture: Langfuse Sovereign Telemetry vs. LangSmith

CAGE standardizes strictly on **Langfuse** for its runtime model observability and compliance telemetry.

- **Why Langfuse**: Langfuse is open-source and self-hosted within each designated Kubernetes cluster and cloud region (`europe-west1`, `asia-southeast1`, `us-central1`), fulfilling strict jurisdictional sovereign data residency mandates (GDPR Art. 44, MAS TRM §4.2, NIST SP 800-53). It also supports CAGE's dual-pipeline telemetry architecture (separating the hot application performance pipeline on port `3000` from the immutable compliance audit attestation pipeline on port `3001`).
- **Why LangSmith is in Dependencies**: `langsmith` is a mandatory upstream dependency of `langchain-core` (which is pulled in by `langgraph` and `nemoguardrails`). It is present purely as a transitive library requirement.
- **Strict Invariant**: LangSmith is **never** used by CAGE application code, and no code under `src/` may import or rely on LangSmith. LangSmith tracing is explicitly disabled across all Kubernetes deployment templates (`deployment/k8s/backend-deployment.yaml.tpl`), Terraform modules (`infra/modules/governed_advisor/main.tf`), and test harnesses (`tests/conftest.py`) via `LANGSMITH_TRACING=false` and `LANGCHAIN_TRACING_V2=false`.

### External Vendor Adapter Standards (Plugin Architecture)

All external vendor adapters and integrations (`src/integrations/provider_*`) **must strictly follow** the design principles, isolation boundaries, and latency budgets specified in [`local/analysis/Secure Plugin & Adapter Architecture Specification.md`](local/analysis/Secure%20Plugin%20%26%20Adapter%20Architecture%20Specification.md):

- **Vendor Isolation**: Vendor packages live exclusively under `src/integrations/{provider_name}/` and must never introduce direct dependencies or imports into the core CAGE kernel (`src/gateway/`).
- **Seam Implementation**: Synchronous gate adapters must implement the canonical `NormativeProvider` protocol (`fetch_baseline`, `validate_fria`, `submit_evidence`) and return CAGE dataclasses (`NormativeBaseline`, `ValidationResult`, `EvidenceSeal`). Asynchronous evidence and attestation providers must implement the `AttestationProvider` or `EnvelopeMapper` protocols.
- **Universal Protocol Conformance**: Every new partner adapter must be registered and validated in the parameterized Universal Protocol Conformance Suite (`tests/test_normative_provider_conformance.py`). This guarantees interface compliance across all regions in CI.
- **Tri-State / Review Mapping**: Upstream non-binary verdicts (`REVIEW`, `ESCALATE`) must be mapped to `ValidationResult(admitted=False, findings=[{"needs_human_review": True, ...}])` to enable native parking in CAGE's `DeferQueue` rather than raising custom exceptions.
- **Fail-Closed Semantics**: Network timeouts, HTTP status errors, and parse failures must fail-closed (`admitted=False`) and populate structured findings with `code="ENDPOINT_ERROR"` or `code="cage.endpoint_error"`.
- **Sidecar & UDS Architecture**: In production deployments, external vendor SDKs (e.g. Node.js engines) run as sidecar containers communicating via Unix Domain Sockets (UDS) to meet sub-millisecond hot-path latency requirements.
- **Hermetic Testing & Schema Validation**: Vendor mocks must validate payloads against vendored JSON schemas and provide 100% hermetic unit tests with mock clients (e.g. `respx`). Live API calls must never run in PR CI.

---

## Documentation Standards

Because CAGE is an illustrative reference architecture and not a live production deployment, all repository documentation must strictly adhere to the following principles:

- **No Internal Operational Tracking:** Do not add or maintain documents that track specific internal deployments, incidents, or team progress (e.g., active POAM trackers, rollback procedures for specific migrations, internal implementation status).
- **Illustrative Patterns Only:** Documents that describe operational procedures (like key rotation, deployment rules, or compensating controls) must clearly include a "Reference Architecture Note" stating they are illustrative templates for adopters.
- **Maintainer Independence:** Documentation should be written for an external adopter to adapt, devoid of maintainer-specific internal cloud project names, timestamps, or specific ticket tracking.
- **Chunked Document Writing:** When creating or updating long documentation files, write content in many small chunks rather than single large writes. This improves reliability of file operations and reduces the risk of truncation or corruption during write operations. Prefer using `apply_diff` with multiple small SEARCH/REPLACE blocks or multiple sequential `write_to_file` calls with append semantics over a single monolithic write.

---

## Answering Questions About This Repository

When explaining repository concepts, reference the authoritative source
documents rather than paraphrasing from memory:

| Topic | Authoritative source |
|---|---|
| Git workflow, branching, commits | [`docs/operations/GIT_WORKFLOW_STANDARDS.md`](docs/operations/GIT_WORKFLOW_STANDARDS.md) |
| Deployment procedures | [`docs/operations/DEPLOYMENT_RULES.md`](docs/operations/DEPLOYMENT_RULES.md) |
| PR requirements | [`.github/pull_request_template.md`](.github/pull_request_template.md) |
| CI pipeline | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |
| Compliance obligations | [`compliance/lula/`](compliance/lula/), [`compliance/oscal/`](compliance/oscal/) |
| POAM tracking | [`docs/POAM.md`](docs/POAM.md) |
| Vendor adapters / Plugin architecture | [`local/analysis/Secure Plugin & Adapter Architecture Specification.md`](local/analysis/Secure%20Plugin%20%26%20Adapter%20Architecture%20Specification.md) |

When explaining compliance posture or security controls:
- CAGE is a reference architecture — clarify that region gates and deployment
  promotion rules are illustrative patterns, not operational obligations for
  this repository.

When asked about secrets or credentials:
- Never provide example values that resemble real credentials.
- Direct to `terraform.auto.tfvars` for secret storage.
- Note that `secretKeyRef` / `secretRef` is required in Kubernetes manifests.

---

## Tool-Specific Configuration

This file is the single authoritative source of truth for agent and contributor standards,
following the open, tool-agnostic `AGENTS.md` convention. 

All modern AI coding assistants consume `AGENTS.md` natively at the repository root:

| Assistant / Tool | Ingestion Path | Behavior |
|---|---|---|
| **Antigravity** | `AGENTS.md` | Ingested natively as global project instructions and behavioral rules. |
| **Roo Code / Cline** | `AGENTS.md` | Ingested automatically into all modes (Code, Architect, Debug, Ask). |
| **Cursor / Copilot / Windsurf** | `AGENTS.md` | Discovered natively at repository root. |

If you use a tool that requires a legacy configuration filename (e.g. `CLAUDE.md`, `.cursorrules`, or `.github/copilot-instructions.md`), create a thin symlink or pointer pointing directly back to this file rather than maintaining a divergent copy of these standards.

---

## Test Execution

### Local and Unit Suite (Offline)

The canonical way to run the full local and unit test suite across multiple workers:

```bash
uv run pytest tests/ -m "local or unit" -n auto --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin --tb=short
# Or via Makefile shortcut:
make test-fast
```
Always launch the test suite with `--dist loadscope` (or `--dist=loadfile`) to ensure proper test file and fixture isolation across workers.

### Fast Local Development & Profiling Reference

| Goal / Workflow | Canonical Command |
|---|---|
| **Fast dev run (parallel, no coverage)** | `uv run pytest tests/ -m "local or unit" -n auto --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin -q` (or `make test-fast`) |
| **Run only last failed tests** | `uv run pytest tests/ -m "local or unit" --lf --dist loadscope -n auto -q` (or `make test-last-failed`) |
| **Profile slowest tests & fixtures** | `uv run pytest --durations=20 --durations-min=1.0` |
| **Full suite with coverage (mirrors CI)** | `uv run pytest tests/ -m "local or unit" -n auto --dist loadscope --cov=src --cov-config=.coveragerc --cov-report=term-missing --cov-fail-under=75` (or `make test-coverage`) |

**High-Throughput / In-Memory Optimization:**
On Linux development hosts (such as the `dev-thin-client` VM), point pytest temporary directory allocations to shared memory (`tmpfs`) to avoid disk lock contention and speed up test runs across 16+ parallel workers:
```bash
uv run pytest tests/ -m "local or unit" -n auto --dist=loadfile --tb=short --basetemp=/dev/shm/pytest
```

### Targeted Test Commands Reference

| Scope / Purpose | Canonical Command |
|---|---|
| **Single test file** | `uv run pytest tests/test_tls_enforcement.py -v` |
| **Specific test method** | `uv run pytest tests/test_tls_enforcement.py::TestTlsProtocolStandards::test_default_client_context_minimum_version -v` |
| **Finance domain plugin tests** | `uv run pytest tests/cage_finance/ -v` |
| **Healthcare domain plugin tests** | `uv run pytest tests/cage_healthcare/ -v` |
| **FTRA & AISVS C9 action classification** | `uv run pytest tests/test_ftra*.py -v` |
| **Import boundary check (Gate G3)** | `uv run python scripts/check_import_boundaries.py --verbose` |
| **NeMo ConfigMap sync** | `make update-nemo-configmap` |
| **Adversarial / Red-team unit tests** | `uv run pytest tests/red_team/ -m "red_team and not integration" -v` |
| **US Federal region posture** | `CAGE_DEPLOYMENT_REGION=US_FED uv run pytest tests/ -m us_fed -v` |
| **EU ECB region posture** | `CAGE_DEPLOYMENT_REGION=EU_ECB uv run pytest tests/ -m eu_ecb -v` |
| **APAC MAS region posture** | `CAGE_DEPLOYMENT_REGION=APAC_MAS uv run pytest tests/ -m apac_mas -v` |
| **No-Direct-Bind BFS model proof** | `uv run python proof/model.py && uv run pytest tests/test_no_direct_bind_proof.py -v` |
| **Distributed CBF formal proof** | `uv run python -m proof.distributed_cbf_model && uv run pytest proof/distributed_cbf_model.py -v` |
| **Static analysis & formatting** | `uv run ruff check . && uv run ruff format --check .` |
| **Type checking** | `uv run mypy src/` |
| **Bandit SAST security scan** | `uv run bandit -r src/ -c pyproject.toml -ll` |
| **STPA artifact freshness** | `uv run python scripts/check_stpa_freshness.py --verbose` |
| **Langfuse posture validation** | `uv run python scripts/verify_langfuse_posture.py --dry-run --posture development` (requires mock env vars; see below) |

### Langfuse Regional & Local Testing Limitations

`scripts/verify_langfuse_posture.py` validates dual-pipeline telemetry isolation (primary application telemetry vs. compliance audit pipeline). Because CAGE strictly enforces secret hygiene, live credentials are never committed or present in local environments.

1. **Local Dry-Run Requirements**:
   Running `verify_langfuse_posture.py` locally or in pre-merge validation requires `--dry-run --posture development` and mock environment variables. If run without these, it will fail with missing variable errors (`GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`, `LANGFUSE_*`):
   ```bash
   export GOOGLE_CLOUD_PROJECT="mock-dev-project"
   _region="${CAGE_DEPLOYMENT_REGION:-US_FED}"
   case "$_region" in
     EU_ECB)    export GOOGLE_CLOUD_LOCATION="europe-west1" ;;
     APAC_MAS)  export GOOGLE_CLOUD_LOCATION="asia-southeast1" ;;
     *)         export GOOGLE_CLOUD_LOCATION="us-central1" ;;
   esac
   export LANGFUSE_HOST="http://localhost:3000"
   export LANGFUSE_PUBLIC_KEY="pk-lf-mock"
   export LANGFUSE_SECRET_KEY="sk-lf-mock"
   export LANGFUSE_COMPLIANCE_HOST="http://localhost:3001"
   export LANGFUSE_COMPLIANCE_PUBLIC_KEY="pk-lf-comp-mock"
   export LANGFUSE_COMPLIANCE_SECRET_KEY="sk-lf-comp-mock"
   uv run python scripts/verify_langfuse_posture.py --dry-run --posture development
   ```
2. **Jurisdictional Region Derivation**:
   `GOOGLE_CLOUD_LOCATION` must be derived from `CAGE_DEPLOYMENT_REGION`:
   - `US_FED` → `us-central1`
   - `EU_ECB` → `europe-west1`
   - `APAC_MAS` → `asia-southeast1`
3. **Live GKE Testing**:
   Live dual-pipeline attestation, trace verification, and SLA timing are validated exclusively against live GKE clusters via port-forwarding (`scripts/port_forward_dev.sh`, forwarding ports `3000` and `3001`) with `uv run pytest tests/ --run-integration`. Local offline tests must keep telemetry tracing disabled (`-p no:langsmith -p no:langsmith_plugin`, `LANGCHAIN_TRACING_V2=false`, `LANGSMITH_TRACING=false`).

### Full Integration Suite Against Live GKE

The canonical way to run the full integration test suite against the live GKE dev cluster:

```bash
# 1. Establish port-forwards to live GKE dev cluster (keep running in background)
bash scripts/port_forward_dev.sh

# 2. In a separate terminal, load env and run full suite
source .env
export CAGE_ENV=dev
export CAGE_DEPLOYMENT_REGION="${CAGE_DEPLOYMENT_REGION:-LOCAL}"
export CAGE_ROUTING_SEAL_SECRET="${CAGE_ROUTING_SEAL_SECRET:-dev-only-insecure-placeholder-not-for-production-use}"
export GOVERNANCE_SALT="${GOVERNANCE_SALT:-dev-only-insecure-placeholder-not-for-production-use}"
export LANGFUSE_POSTURE_DRY_RUN=true
uv run pytest tests/ --run-integration -v --tb=short
```

Key facts:
- `scripts/port_forward_dev.sh` establishes auto-reconnecting `kubectl port-forward` tunnels: OPA (8181), Langfuse API/UI (3001/3000), vLLM fast (8001/18081), vLLM reasoning (8000/18082), Gateway (8080), backend (18080), Redis (6379), Compliance Bridge (3002).
- Requires a valid `kubectl` context pointing to `governance-cluster-2` in `us-central1-a`.
- `.env` at the repo root is loaded automatically by `port_forward_dev.sh` and `tests/conftest.py`.
- Last known result (2026-08-10): **2553 passed, 51 skipped, 1 failed** in ~9m25s. The 51 skips are region/OPA-gated integration tests; the 1 failure was a test-isolation bug (cache leak in `tests/test_red_teaming.py::mock_thresholds` fixture), not a GKE connectivity issue.
- Always use `uv run pytest`, never bare `pytest`.

### Staging Lifecycle Validation (POAM-024 Closure)

**Status**: Provisioned 2026-08-29

The `staging` environment is an ephemeral pre-production validation tier that proves full security posture at dev-scale cost before promoting to production:

```bash
# Automated lifecycle (recommended)
./scripts/staging_lifecycle.sh

# Manual deployment
./deploy_all.sh --target gcp-gke --env staging --auto-approve

# Manual teardown
cd infra/targets/gcp-gke
terraform destroy -var-file=staging.tfvars -auto-approve
```

**What staging validates** (ISO 42001 §A.5.3 CA-2 pre-production validation):
- All 31 Lula validation gates pass at 1-replica scale
- NIST SP 800-53 controls enforced without HA overhead
- Cluster-scoped controls active (Binary Authorization, PSS restricted, CMEK, audit logs)
- Regional compliance postures (US_FED, EU_ECB, APAC_MAS) validated

**Key characteristics**:
- **Cost**: ~$2-4 per validation cycle (20-30 minutes runtime)
- **Hardware**: Dev-scale (e2-standard-4 nodes, pd-standard disks, GPU scale-to-zero)
- **Security**: Full prod posture (`enable_nist_compliance=true` for US_FED, Binary Authorization, audit logging, CMEK, PSS restricted)
- **HA**: Decoupled (`enable_high_availability=false`, 1 replica per service, standalone Redis)
- **Lifecycle**: Ephemeral (`enable_deletion_protection=false`, allows teardown)

**Automation workflow** ([`scripts/staging_lifecycle.sh`](scripts/staging_lifecycle.sh)):
1. **Phase 1**: Provision staging with `./deploy_all.sh --env staging`
2. **Phase 2**: Wait for cluster readiness (`kubectl wait --for=condition=Ready`)
3. **Phase 3**: Lula validation (all 31 gates, exit on failure)
4. **Phase 4**: Region posture tests (`CAGE_DEPLOYMENT_REGION={US_FED,EU_ECB,APAC_MAS}`)
5. **Phase 5**: Cluster-scoped control verification (BinAuthz, PSS, CMEK, audit logs)
6. **Phase 6**: Teardown (`terraform destroy -var-file=staging.tfvars`)

See [`infra/targets/gcp-gke/staging.tfvars`](infra/targets/gcp-gke/staging.tfvars) for configuration and [`docs/operations/DEPLOYMENT_DECISION_RECORD.md`](docs/operations/DEPLOYMENT_DECISION_RECORD.md) ADR-004 for design rationale.

### Nightly CI Without Live GKE

**Verdict: No new nightly workflow is needed.**

- The `local`/`unit` marker subset (~90%+ of the 2553 passing tests) already runs on every push/PR via the existing `pytest-logic` job in all three region postures (`.github/workflows/ci.yml` lines 87–134). A dedicated nightly run of the same markers adds negligible incremental regression-detection value over what is already gated on `main` before merge.
- Tests that genuinely require live GKE (live OPA policy evaluation, Langfuse SLA timing, CMEK/pod-restart checks, real backend accuracy) **cannot be replaced** by a mock-only nightly — these are the `integration`-marked corpus and the 51 skips in the full run.
- Existing CI already covers what a nightly would target: `pytest-logic` (mock/unit, every push), `ai600-unit-tests` (red-team mock, every push), `locust-load-test` (nightly load test).
- **Practical guidance**: treat `pytest-logic` + `ai600-unit-tests` (GKE-independent, secret-free) as the authoritative daily regression gate. Reserve the live-GKE `integration-smoke` job, manual full-suite runs (`port_forward_dev.sh` + `uv run pytest tests/ --run-integration`), and **staging lifecycle validation** (`./scripts/staging_lifecycle.sh`) for periodic live-service validation.
