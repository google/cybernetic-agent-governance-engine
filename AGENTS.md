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

When asked to commit or push directly to `main` or `rc-v*`, **refuse** and respond:

```
Direct commits to `main` are not allowed. I'll create a feature branch instead:

git checkout -b <type>/<description>

After committing your changes, I'll push this branch and open a pull request.
The pre-push hook and CI will enforce this rule.
```

Always validate the branch name matches the patterns below before creating it.

### Branch Strategy Enforcement

This repository enforces branching rules through multiple layers:

**Layer 1: Local Git Hooks** (opt-in for humans, N/A for AI agents)

Human contributors run once after cloning:
```bash
bash scripts/setup_git_hooks.sh
```

This installs `commit-msg` (rejects non-Conventional-Commits) and `pre-push` (blocks direct pushes to `main`).

AI agents cannot install hooks. Instead, agents must:
- Never suggest `git push origin main` or committing directly to `main`
- Always create a feature branch with a compliant name before making changes
- Validate commit messages match Conventional Commits before calling `git commit`

**Layer 2: CI Validation** (enforced for all)

[`squash-merge-guard`](.github/workflows/ci.yml:46) fails any build where a merge commit reaches `main`. [`branch-name-validator`](.github/workflows/ci.yml) (when added) will reject PRs from branches with non-compliant names.

**Layer 3: Branch Naming Validation** (enforced by agents)

Before creating a branch, validate the name matches one of these patterns:
- `feat/<description>` — new feature
- `fix/<description>` — bug fix
- `docs/<description>` — documentation
- `refactor/<description>` — code restructuring
- `ci/<description>` — CI/CD changes
- `test/<description>` — test additions
- `chore/<description>` — maintenance
- `hotfix/<version>-<description>` — production hotfix (e.g. `hotfix/2.0.1-redis-timeout`)
- `spike/<description>` — experiment

Where `<description>`:
- Is lowercase kebab-case
- Contains only `[a-z0-9-]`
- Is ≤ 30 characters
- Does not end with a hyphen

**Reject these patterns:**
- `feature/...` (use `feat/`)
- `bugfix/...` (use `fix/`)
- Any uppercase letters
- Underscores
- CamelCase
- Random names without prefix

**Example validation:**
```python
import re

# Hotfix has different structure (version-desc), so use alternation
pattern = r"^(feat|fix|docs|refactor|ci|test|chore|spike)/[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?$|^hotfix/v?\d+\.\d+\.\d+-[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?$"
assert re.match(pattern, "feat/redis-limiter")  # ✅
assert re.match(pattern, "hotfix/2.0.1-redis-fix")  # ✅
assert not re.match(pattern, "random-branch")  # ❌
assert not re.match(pattern, "Feature/Thing")  # ❌
```

### Agent Workflow: Enforcing Branch Strategy

When a user asks you to make code changes:

1. **Check current branch:**
   ```bash
   git symbolic-ref --short HEAD
   ```

2. **If on `main` or `rc-v*`:**
   - **DO NOT** make commits
   - **DO** create a properly-named feature branch first
   - Explain: "You're on a protected branch. I'll create a feature branch."

3. **If on a feature branch with an invalid name:**
   - **STOP** and ask: "This branch name doesn't follow the project's convention. Should I create a new branch with a compliant name like `feat/<description>`?"

4. **If on a valid feature branch:**
   - Proceed with changes
   - Validate commit messages before committing
   - When pushing, confirm: "I'll push to `origin/<branch-name>` (not `main`)"

5. **After pushing:**
   - Offer to open a PR
   - Remind: "Use 'Squash and merge' when merging"

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

Correct:
```bash
uv run pytest
uv run pytest tests/ -m "local or unit" -n auto --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin --tb=short
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
When background port-forwards are running (such as those started via `scripts/port_forward_staging.sh` or `scripts/port_forward.sh`), localhost ports (Redis `6379`, OPA `8181`, Langfuse `3000`/`3001`, Gateway `8080`, Compliance Bridge `3002`, Advisor `8081`, vLLM `8000`/`8001`) are actively bridged to the live GKE cluster. Local unit tests (`pytest tests/ -m "local or unit"`) that do not strictly isolate network sockets can inadvertently connect to the live GKE cluster and encounter live state (e.g., existing fence epochs, active cache keys), causing unexpected assertions like `assert cbf._last_seen_epoch == 42` reading live Redis epoch `17`.
- **Before running pure local/unit tests**: Verify no background tunnels are running (`ps aux | grep port-forward`), or terminate them if isolated offline execution is desired (`pkill -f "kubectl port-forward"`).
- **For integration testing against live GKE**: Launch persistent tunnels with `./scripts/port_forward_staging.sh --daemon` and run the suite with `--run-integration`. Set `CAGE_ENV=test` (enables local HMAC fallback mode so tests do not halt on local Cloud KMS IAM permission checks while accessing live GKE services) and export `CAGE_API_KEY=cage-staging-test-key` matching the cluster secret. See [§ Live GKE Cluster Integration Suite](#live-gke-cluster-integration-suite).

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
gcloud builds submit --config deployment/docker/cloudbuild.gateway.yaml

# APPROVED for local/agnostic
./deploy_all.sh --target agnostic --env dev
```

**Never suggest for GKE:**
- `docker build ... && docker push ...` or `docker-compose build && ... push`
- `--platform linux/amd64` local/BuildKit cross-compilation
- `kubectl apply` without a preceding Cloud Build step

**Cloud Build config files:** `deployment/docker/cloudbuild.gateway.yaml`
(gateway), `deployment/docker/cloudbuild.vllm.yaml` (vLLM),
`deployment/docker/cloudbuild.lula.yaml` (Lula).

Terraform state is in a GCS backend (`infra/targets/gcp-gke/main.tf`).
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
3. **marker-contract-check** — a collected test carries no selection marker and would be invisible to every CI gate. Fix: add `pytestmark = [pytest.mark.unit, pytest.mark.local]` (or the appropriate selection marker) after the module's import block. Never exclude the file from collection to silence this.
4. **import-boundary-check (Gate G3 in `lint`)** — Layer 1 (`src/gateway/`) imported from Layer 2 (`src/cage_*`), Layer 3 (`src/compliance_bridge/`, or module-scope `src.integrations`), or Layer 4 (`src/governed_financial_advisor/`). Module-scope `src.integrations` imports in the kernel are forbidden; function-scope lazy factory imports are permitted only in allowlisted files (`normative_provider.py`, `evidence/factory.py`). Fix: run `uv run python scripts/check_import_boundaries.py --verbose` and sever illegal upward imports to maintain kernel/plugin isolation, or convert to function-scope lazy import in an allowlisted factory.
5. **nemo-freshness-check** — `deployment/k8s/nemo-rails-configmap.yaml` is out of sync with `config/rails/actions.py`. Fix: run `make update-nemo-configmap`.
6. **stpa-freshness-check** — STPA source changed without regenerating artifacts. Fix: run `scripts/check_stpa_freshness.py`.
7. **langfuse-posture-check** — requires mock cloud and Langfuse environment variables in local/offline environments. Fix: supply mock project/keys with derived `GOOGLE_CLOUD_LOCATION` and run `python scripts/verify_langfuse_posture.py --dry-run --posture development` (see [Langfuse Regional & Local Testing Limitations](#langfuse-regional--local-testing-limitations)).
8. **pytest** — address the failing test before suggesting any workaround. Always verify:
   - **No active port-forward contamination**: ensure `kubectl port-forward` to dev Redis (6379) / OPA (8181) is not polluting local test state.
   - **Canonical module paths**: verify imports use post-v3 locations (`src.gateway.governance.causal.gatekeeper`, `src.gateway.governance.reconciliation.daemon`, `src.gateway.governance.safety.cbf_engine`).
   - **Governor contracts**: verify `SymbolicGovernor` instantiations provide `safety_filter`, `consensus_engine`, and context parameters.
9. **security-scan** — rotate the credential or address Bandit SAST / dependency CVE findings; never suggest suppressing the scan.

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
| **Layer 1: Kernel** | `src/gateway/` | **STERA Admissibility Engine**, core governance dispatch loop, standing assembly, consensus engine, CBF engine, evidence accumulator, routing, and audit rails. | **Strictly domain-agnostic and vendor-neutral.** Must NEVER import from `src/cage_*` (Layer 2), `src/compliance_bridge/` (Layer 3), or `src/governed_financial_advisor/` (Layer 4). Must NOT import vendor SDKs (`google.cloud`, `boto3`, `azure`, `langfuse`). Enforced in CI by Gate G3 (`scripts/check_import_boundaries.py`). Must not hardcode domain verbs (e.g. `execute_trade`) or domain data structures. |
| **Layer 2: Domain Plugins** | `src/cage_{domain}/` (e.g. `src/cage_finance/`, `src/cage_healthcare/`) | Domain-specific tiers (`GovernanceTierPlugin`), domain action registries, ontologies, policies, and causal graphs. | Provides immutable domain tiers to the kernel via `SymbolicGovernor(domain_tiers=...)` or domain plugin tier factories. Encapsulates domain vocabulary and semantics without polluting the kernel. |
| **Layer 3: Integrations & Rails** | `src/integrations/`, `src/cage_finance/rails/`, `src/compliance_bridge/` | External vendor normative/attestation adapters, durable sinks (ClickHouse, GCS, S3), NeMo Guardrails, Langfuse telemetry. | Adheres to the Secure Plugin & Adapter Architecture Specification. Communicates via canonical dataclasses. |

**The Three-Layer Split Rule:**
- **Layer 1 (Kernel)**: Home of the **STERA Admissibility Engine**. Code that can fail closed unsafely lives in the kernel. Code covered by TLA+ proofs, formal CBF math, or core NIST control assertions. Code that holds Redis Lua scripts, KMS envelope signing, or fence epoch tracking. The STERA execution boundary (the `seams/` zero-dependency protocols) must NEVER be bypassed by vendor adapters or Layer 2 domain plugins.
- **Layer 2 (Domain Plugin)**: Code that merely names domain concepts (actions, symbols, tickers, dosages), Rego domain packages, domain Pydantic models, or ledger providers.
- **Config**: Numbers, thresholds, citations, and STPA hazard declarations (`config/`).

**Decision test for ambiguous code:** *"If two domains had different copies of this, would a security fix have to be applied twice?"* If yes → Layer 1 (Kernel).

### FTRA (Tier 0.5 — Commencement-Time Reachability & Action Taxonomy)

Action reachability analysis and registry integrity controls live in `src/gateway/governance/ftra/`:
- **Action Taxonomy**: Actions are classified into canonical categories: `REVERSIBLE`, `IRREVERSIBLE`, and `EXTERNALLY_REVERSIBLE` (per OWASP AISVS C9).
- **Fail-Closed Boundary**: Any unknown or unclassified action must fail closed. Read-only actions bypass heavy barrier verification only when explicitly verified as read-only.
- **Registry Integrity**: Registries must be signed using KMS/JCS canonicalization, preventing untracked runtime capability escalation.

### Canonical Module Namespaces (v3.0.1 Architecture)

Refactoring across v3.0.1 extracted domain mechanisms into domain plugins and modularized gateway subpackages. All imports and test mocks must use these canonical locations:

| Component | Canonical Location | Deprecated / Relocated Path (Do Not Import) |
|---|---|---|
| Causal Gatekeeper | `src.gateway.governance.causal.gatekeeper` | `src.gateway.governance.causal_gatekeeper` |
| Reconciliation Daemon | `src.gateway.governance.reconciliation.daemon` | `src.cage_finance.compliance.reconciliation_worker` |
| FTRA Package | `src.gateway.governance.ftra` | Legacy flat imports in root governance |
| Financial Tiers | `src.cage_finance.tiers` | Hardcoded blocks in `symbolic_governor.py` |
| Healthcare Tiers | `src.cage_healthcare.tiers` | N/A (new domain plugin) |
| Evidence Stream | `src.gateway.governance.evidence.stream` | `src.compliance_bridge.evidence_stream` |
| Evidence Cold Store | `src.gateway.governance.evidence.cold_store` | Legacy ad-hoc storage modules |
| ISO Control Registry | `src.gateway.governance.iso_control` | `src.compliance_bridge.types` control mappings |

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
- **Trust Anchors — Never Verify Against an Embedded Key**: A signature must never be verified against a public key supplied by the document being verified. A forged receipt controls its entire body, including any embedded key, so verifying against it proves nothing. Resolve keys by `kid` from an independently-fetched key manifest, cached out-of-band. **Enforce this in the type system, not in review comments**: the verification function accepts a resolved key object, and only the cache lookup may produce one. An embedded key may be compared for diagnostics and logged on mismatch, but must never reach the verifier. On unknown `kid`, refresh the manifest **once**, then fail closed — never fall back to the embedded key, never downgrade to a warning.
- **Resolution Status Is Not Verification Status**: A successful fetch proves a receipt exists and is well-formed; it does not prove the signature. Adapters return `UNVERIFIED` on successful resolution and promote to `VERIFIED` only after cryptographic verification succeeds. Where verification is unimplemented, return `UNVERIFIED` — never `VERIFIED` with a comment promising a later fix.
- **Refusals Are Primary Evidence**: A governance engine's refusals are the proof it intervened. If only `ALLOW` decisions reliably enter the tamper-evident chain, the audit record systematically over-represents permitted actions and an auditor must take the operator's unsigned word on every block. DENY and PAUSE receipts must enter the evidence chain with the same completeness as approvals — the full proof object, not a lossy summary — serialized from one path rather than rebuilt at each call site. **Ordering constraint**: wire evidence *citations* only after the chain they cite is complete. Emitting `link[rel="evidence"]` into a chain missing every DENY produces references to an incomplete record, which is worse than emitting none because it looks complete.

### Partner Adapter Branding & Trademark Policy ("Generic in Code, Specific in Prose")

CAGE adheres to open-source trademark standards and architectural vendor neutrality:

1. **Code & Structural Architecture (Strict Vendor Neutrality):**
   - **Layer 1 Governance Kernel (`src/gateway/`)**: Must remain 100% vendor-neutral in all executable code, variables, function names, enum members (e.g. `EXTERNAL_HOLD` rather than vendor-specific names), Redis keys, and environment variables. Enforced in CI by Gate G8 (`scripts/check_vendor_brands.py`) and Gate G3 (`scripts/check_import_boundaries.py`).
   - **Layer 3 Package Paths & Namespaces (`src/integrations/`)**: Must use anonymized namespaces and package import paths (e.g., `provider_01`, `actuator_01`, `provider_05`) rather than partner brand names to preserve import stability across branches and prevent structural coupling.

2. **Documentation & Attribution (Descriptive Fair Use):**
   - Real partner names (e.g., Archytan, NexArt, FlowSignal, Veritas, VEIP) are explicitly permitted and encouraged in Layer 3 prose, including adapter `README.md` files, release notes, and architecture guides.
   - All partner adapter READMEs must follow the `provider_05` reference convention with an explicit **Naming note** block directly below the reference-architecture header, crediting the partner while explaining that the package path remains anonymized for import stability.

3. **Interoperability & Compliance Exceptions (Functional Necessity):**
   - **Wire Protocols**: Where third-party identifiers are load-bearing parts of cryptographic protocol constants or HTTP headers (e.g., `X-Archytan-Signatures`, `ARCHYTAN_QUORUM_V1:`, `ARCHYTAN_ASSERTION_V1:`), they are retained as functional protocol requirements.
   - **Compliance Artifacts**: Historical test fixtures, OSCAL component definitions, and validation manifests (e.g., `lula-validation-flowsignal.yaml`) retain partner names to maintain verifiable audit trails and regulatory traceability.

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
| Partner branding & trademark policy | [Partner Adapter Branding & Trademark Policy](#partner-adapter-branding--trademark-policy-generic-in-code-specific-in-prose) |

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

### Live GKE Cluster Integration Suite

To execute the test suite against the live GKE cluster (staging environment):

1. **Verify Kubectl Context**:
   Ensure `kubectl` is pointed at the staging cluster:
   ```bash
   kubectl config current-context  # e.g., gke_laah-cybernetics_us-central1-a_cage-staging
   ```

2. **Start Daemon Port-Forwards**:
   Launch auto-reconnecting tunnels in daemon mode to keep persistent background loops across all services:
   ```bash
   ./scripts/port_forward_staging.sh --daemon
   ```
   Verify port reachability via:
   ```bash
   ./scripts/port_forward_staging.sh --status
   ```
   *Forwarded Endpoints*:
   - Gateway: `http://localhost:8080` (HTTP/gRPC)
   - Governed Financial Advisor backend: `http://localhost:8081` (service port 80)
   - Compliance Bridge: `http://localhost:3002` (service port 80, container port 3001)
   - Langfuse UI & API: `http://localhost:3000` / `http://localhost:3001` (service port 3000)
   - OPA Policy Engine: `http://localhost:8181`
   - Redis: `localhost:6379`
   - vLLM Fast (Qwen2.5-7B): `http://localhost:8001` (and `http://localhost:18081/v1`)
   - vLLM Reasoning (DeepSeek R1): `http://localhost:8000` (and `http://localhost:18082/v1`)

3. **Cluster Invariant Requirements**:
   - **Compliance Bridge `LANGFUSE_HOST`**: In the GKE deployment, `LANGFUSE_HOST` must explicitly declare port `3000` (`http://langfuse-web.governance-stack.svc.cluster.local:3000`), as the `langfuse-web` service listens on 3000 (not 80). Without `:3000`, metrics and SLA queries time out.
   - **Advisor Auth Token**: `CAGE_API_KEY` must match the cluster secret (`cage-staging-test-key` in staging).
   - **Local Workstation KMS Mode**: Set `CAGE_ENV=test` on developer workstations when invoking pytest. This allows tests to exercise live GKE services (Redis, OPA, Compliance Bridge, Gateway, Advisor, vLLM) without requiring `cloudkms.cryptoKeyVersions.viewPublicKey` IAM permissions on the local developer's GCP credentials.

4. **Canonical Invocations**:
   - **Full test suite (unit + live integration)**:
     ```bash
     source .env && \
     export COMPLIANCE_BRIDGE_URL=http://localhost:3002 \
            BACKEND_URL=http://localhost:8081 \
            LANGFUSE_HOST=http://localhost:3001 \
            CAGE_API_KEY=cage-staging-test-key \
            CAGE_ENV=test && \
     uv run pytest tests/ --run-integration -n auto --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin --tb=short
     ```
   - **Integration-marked tests only**:
     ```bash
     source .env && \
     export COMPLIANCE_BRIDGE_URL=http://localhost:3002 \
            BACKEND_URL=http://localhost:8081 \
            LANGFUSE_HOST=http://localhost:3001 \
            CAGE_API_KEY=cage-staging-test-key \
            CAGE_ENV=test && \
     uv run pytest tests/ -m integration --run-integration -n auto --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin --tb=short
     ```
   - **Single integration suite**:
     ```bash
     ENVIRONMENT=integration COMPLIANCE_BRIDGE_URL=http://localhost:3002 \
     uv run pytest tests/test_compliance_bridge_integration.py --run-integration -v --tb=short
     ```

### Verification Rules (fail-closed)

**Full-gate before green.** A change is not complete until the whole `make test-fast`
suite passes — not merely the tests in the touched package. Running only the
package you edited is how contract drift reaches a branch head: a required-field
addition or a changed constructor signature breaks construction sites in
*other* packages, and no scope-local run will show it.

**Attribute failures to the merge base.** Before characterising a failure as
pre-existing, run the affected files on the merge base and quote the result.
"Pre-existing on my branch" and "pre-existing on `main`" are different claims,
and only the second one excuses the failure.

**Grep after renaming.** After renaming any symbol that crosses a module
boundary, run `rg -n '<old_symbol>' src/` and require **zero** results before
declaring done. A comparison against a string literal is invisible to `mypy`
and to the test suite of the package that owns the symbol — a half-applied
rename compiles, passes its own tests, and silently becomes dead code. Both
sides of an emitter/matcher contract must change in the **same commit**, or the
path fails open into a generic branch.

### Pytest Marker Contract (fail-closed)

Every collected test must carry at least one **selection marker**:
`local`, `unit`, `integration`, `live_external`, `partner_integration`, `chaos`, or `load`.
A collection-time guard in `tests/conftest.py` raises `pytest.UsageError` and
aborts the run if any test is unmarked — an unmarked test is collected locally
but silently excluded from every CI gate, which is a fail-open posture the
project does not accept.

Facet markers (`partner`, `slow`, `regression`, `red_team`, `layer_isolation`, `financial`,
`healthcare`, `us_fed`, `eu_ecb`, `apac_mas`) are **additive** and never satisfy
the contract on their own.

Default for a new hermetic test module:

    pytestmark = [pytest.mark.unit, pytest.mark.local]

`local` = runs with no network or live service. `unit` = narrow scope.
They are orthogonal, not synonyms. See `tests/README.md § Pytest Markers`.
Never disable the `marker-contract-check` CI job to make a build pass.

### Fast Local Development & Profiling Reference

| Goal / Workflow | Canonical Command |
|---|---|
| **Fast dev run (parallel, no coverage)** | `uv run pytest tests/ -m "local or unit" -n auto --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin -q` (or `make test-fast`) |
| **Run only last failed tests** | `uv run pytest tests/ -m "local or unit" --lf --dist loadscope -n auto -q` (or `make test-last-failed`) |
| **Profile slowest tests & fixtures** | `uv run pytest --durations=20 --durations-min=1.0` |
| **Full suite with coverage (mirrors CI)** | `uv run pytest tests/ -m "local or unit" -n auto --dist loadscope -p no:langsmith -p no:langsmith_plugin --cov=src --cov-config=.coveragerc --cov-report=term-missing --cov-fail-under=70` (or `make test-coverage`) |

### Targeted Test Commands Reference

| Scope / Purpose | Canonical Command |
|---|---|
| **Single test file** | `uv run pytest tests/test_tls_enforcement.py -v` |
| **Specific test method** | `uv run pytest tests/test_tls_enforcement.py::TestTlsProtocolStandards::test_default_client_context_minimum_version -v` |
| **Marker contract check (all tests marked)** | `uv run pytest tests/ --collect-only -q --no-cov -n0 -p no:langsmith -p no:langsmith_plugin` |
| **Finance domain plugin tests** | `uv run pytest tests/cage_finance/ -v` |
| **Finance domain plugin tests (by marker)** | `uv run pytest tests/ -m financial -v` |
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
| **Live GKE full integration suite** | `source .env && export COMPLIANCE_BRIDGE_URL=http://localhost:3002 BACKEND_URL=http://localhost:8081 LANGFUSE_HOST=http://localhost:3001 CAGE_API_KEY=cage-staging-test-key CAGE_ENV=test && uv run pytest tests/ --run-integration -n auto --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin --tb=short` |
| **Live GKE integration-only tests** | `source .env && export COMPLIANCE_BRIDGE_URL=http://localhost:3002 BACKEND_URL=http://localhost:8081 LANGFUSE_HOST=http://localhost:3001 CAGE_API_KEY=cage-staging-test-key CAGE_ENV=test && uv run pytest tests/ -m integration --run-integration -n auto --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin --tb=short` |
| **GKE port-forward daemon** | `./scripts/port_forward_staging.sh --daemon` |

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
   Live dual-pipeline attestation, trace verification, and SLA timing are validated exclusively against live GKE clusters via port-forwarding (`scripts/port_forward_staging.sh`, forwarding ports `3000` and `3001`) with `uv run pytest tests/ --run-integration`. Local offline tests must keep telemetry tracing disabled (`-p no:langsmith -p no:langsmith_plugin`, `LANGCHAIN_TRACING_V2=false`, `LANGSMITH_TRACING=false`).

### Running Live Integration Tests in Staging Posture

Running integration tests against a live GKE cluster deployed in **staging posture** (`CAGE_ENV=staging`) verifies real service contracts (Gateway, OPA, Redis, Compliance Bridge, Langfuse, ClickHouse, MCP tools) across live network boundaries.

#### 1. Cluster Prerequisites & Port-Forward Daemon

Before launching integration tests, verify the `kubectl` context points to the staging cluster (e.g. `cage-staging` in `us-central1-a`) and all non-GPU services are Running:

```bash
kubectl get pods -n governance-stack
```

Start the port-forward daemon in the background:

```bash
bash scripts/port_forward_staging.sh --daemon
# Or run in foreground:
bash scripts/port_forward_staging.sh
```

**Port-Forward Features & Inactive GPU Handling:**
- The script automatically checks `kubectl get endpointslice` (`has_endpoints`) and detects whether services have ready endpoints before opening ports.
- **GPU Scaling Invariant**: In staging clusters, the GPU node pool (`gke-gpu-pool`) is typically scaled to 0 replicas to conserve compute costs. The script automatically detects 0 endpoints for `vllm-service` (port `8001`) and `vllm-reasoning` (port `8000`) and skips them, preventing tight reconnect loops from overwhelming the Kubernetes API server.
- Supported active ports: OPA (`8181`), Langfuse UI/API (`3000`/`3001`), Gateway (`8080`), Backend/GFA (`8081`), Compliance Bridge (`3002`), Redis (`6379`).

#### 2. Test Harness Configuration & KMS Signing in Staging

In staging mode, `SymbolicGovernor` enforces asymmetric Cloud KMS signature verification (`KMS_GOVERNANCE_KEY`). Local workstations running pytest do not possess GKE Workload Identity IAM permissions to sign with Cloud KMS:
- **Client Test Posture**: In `tests/conftest.py`, running client test commands with `CAGE_ENV=test` allows the test harness to use software-backed HMAC/SHA256 signing for local assertions while directing all network requests to live cluster endpoints via localhost tunnels (`BACKEND_URL=http://localhost:8081`, `GATEWAY_URL=http://localhost:8080`, `OPA_URL=http://localhost:8181`, `REDIS_URL=redis://localhost:6379/0`).
- **KMS Public Key Verification**: If verifying Gateway responses signed with the staging KMS key, extract the public key PEM from the running gateway pod:
  ```bash
  kubectl exec -n governance-stack deploy/gateway -c gateway -- cat /tmp/kms_governance_public.pem > /tmp/kms_governance_public.pem
  export KMS_GOVERNANCE_PUBLIC_PEM=/tmp/kms_governance_public.pem
  ```

#### 3. Worker Concurrency Limits on Port-Forward Tunnels

**CRITICAL RULE: Never use `-n auto` against port-forwarded tunnels.**
On multi-core developer workstations, `-n auto` spawns 16+ parallel pytest workers. Hammering localhost port-forward tunnels with 16 concurrent workers floods TCP connection pools, causing connection resets, Redis timeouts, and spurious `503 Service Unavailable` errors from Compliance Bridge.
- Always constrain concurrency to **`-n 2` or `-n 4`** with `--dist loadscope`:
  ```bash
  uv run pytest tests/ -m integration --run-integration -n 2 --dist loadscope
  ```

#### 4. Partner Integration Tests Isolation

External partner integration tests hitting third-party vendor APIs (such as `tests/test_provider_01_live.py`) are tagged with the **`partner_integration`** selection marker (and `live_external`), **NOT** the default `integration` marker:
- Running `uv run pytest tests/ --run-integration` or `-m integration` **excludes** partner tests by default.
- To execute partner integration tests when external sandbox credentials are configured:
  ```bash
  uv run pytest -m partner_integration --run-partner-integration
  # Or with live external flag:
  uv run pytest tests/test_provider_01_live.py --run-live-external
  ```

#### 5. Expected Outcomes for GPU-Dependent Tests

When the staging cluster's GPU node pool is scaled down to 0 replicas:
- **`tests/test_langfuse_evaluation.py`**: Cleanly auto-skips with `vLLM judge endpoint is not reachable — GPU pod likely Pending in dev/staging posture`.
- **`tests/test_gateway_connectivity_live.py::test_chat_proxy`**: Cleanly auto-skips when vLLM backend is unreachable.
- **`tests/test_agent_accuracy.py`**: Will fail or return `401 Unauthorized` / connection error because the full financial advisor graph requires live vLLM inference and cluster-configured `CAGE_API_KEY`.
- **Decision Rule**: Do **not** treat GPU-disabled skips or inference failures as software regressions when running against clusters with scaled-down GPU pools.

#### 6. Canonical Staging Integration Test Workflow

Follow this step-by-step workflow for comprehensive staging validation:

```bash
# Step 1: Health smoke test across all port-forwarded cluster endpoints
uv run python scripts/test_live_gke_services.py

# Step 2: Live end-to-end governance flow & Langfuse trace ingestion
uv run python scripts/test_gke_e2e_flow.py

# Step 3: OPA Rego governance policies against live cluster OPA (20/20 checks)
uv run pytest tests/test_trade_governance_rego.py --run-integration -v

# Step 4: Redis durability, maxmemory, and DB0/DB1 namespace isolation
uv run pytest tests/test_redis_eviction_envelope.py --run-integration -v

# Step 5: Compliance Bridge & MCP live tool execution (constrained concurrency)
uv run pytest tests/test_compliance_bridge_smoke.py tests/test_trades_mcp.py tests/test_evaluator_mcp.py --run-integration -v
uv run pytest tests/test_compliance_bridge_integration.py --run-integration -n 2 --dist loadscope -v

# Step 6: Gateway TLS enforcement and connectivity
uv run pytest tests/test_gateway_connectivity_live.py --run-integration -v

# Step 7: Teardown port-forward daemon after testing
bash scripts/port_forward_staging.sh --stop
# Or kill background daemon:
pkill -f "kubectl port-forward"
```

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
- **Practical guidance**: treat `pytest-logic` + `ai600-unit-tests` (GKE-independent, secret-free) as the authoritative daily regression gate. Reserve the live-GKE `integration-smoke` job, manual full-suite runs (`scripts/port_forward_staging.sh` + `uv run pytest tests/ --run-integration`), and **staging lifecycle validation** (`./scripts/staging_lifecycle.sh`) for periodic live-service validation.

---

## Agent Governance & Cost Guardrails

### Operational Roles & Model Tier Enforcement

To eliminate runaway frontier model billing, avoid quota lockouts, and eliminate multi-window context friction, this repository standardizes on the **Unified Sidebar + Passive Keystroke Daemon** architecture:

1. **Unified Sidebar Engine (Roo Code / Zoo Code)**: 100% of conversational engineering, codebase exploration, code diffs, and terminal execution run inside Zoo Code to eliminate the "two-inbox problem" and ensure strict governance under `.roomodes`:
   - **Exploration & Discovery (`ask` mode)**: Powered by **Gemini Flash via Google Cloud Vertex AI ADC** (`gemini-2.5-flash` or `gemini-3-flash`). Executes high-speed AST indexing and repository sweeps at pay-as-you-go rates (~$0.001/query), completely bypassing consumer subscription quota freezes and 5-hour rolling lockouts.
   - **Targeted Implementation (`code` mode)**: Powered by **Claude 3.7 Sonnet**. Governed by active Cost & Search Gates that intercept unstructured searches and direct them to `ask` mode before paid tokens are spent.
   - **Standard Debugging (`debug` mode)**: Powered by **Claude 3.7 Sonnet** for syntax, failed assertions, and unit tests. Enforces a 2-turn fail-fast threshold.
   - **Surgical Escalation (`escalated-architect`, `escalated-debug`)**: Powered by **Claude 5 (Opus 5 / Fable 5.1)** for safety-critical state machines, CBF formal proofs, or deep concurrency defects. Strictly capped at 1–3 turns with pre-filtered context.

2. **Ambient Keystroke Completion Daemon (Google Antigravity)**: Installed strictly as a headless, passive background daemon for **unmetered inline tab completions (ghost text)** inside editor buffers. Its chat panel remains permanently closed during active development to preserve unified telemetry, single-point audit logging, and `.roomodes` enforcement.

3. **Ask Mode Restriction**: Never point conversational or Q&A modes to Opus or Fable. Use Gemini Flash or Claude Haiku.

### Three Rules to Make Claude 5 Affordable

When invoking Claude 5 in `escalated-architect` or `escalated-debug` mode, strictly satisfy these three conditions to keep monthly frontier spend governed:
1. **Pre-Filter Context in the Free Tier (Antigravity + Gemini Flash)**: Never allow Claude 5 to crawl directories or search for files. Use Gemini Flash in Antigravity to index the repo, locate the exact modules, and produce a concise $\le$50-line briefing. Provide only that briefing and the 1–2 target files to Claude 5.
2. **Keep Context Strictly Under 200k Tokens**: Crossing the 200k boundary triggers the 200,001–1,000,000 token pricing tier with severe cache-write and cache-read surcharges. Keep active contexts small and tightly bounded.
3. **Execute 1–3 Turns, Then Switch Back to Sonnet**: Treat Claude 5 like an external consulting architect. Let it generate the specification or identify the root cause within 1–3 turns. The moment the design plan or bug diagnosis is produced, switch Roo Code / Zoo Code back to `code` mode (Sonnet) to implement the diff and run tests.

### Hard Anti-Loop & Cost Invariants

1. **5-Step Execution Cap**: Never exceed 5 consecutive autonomous tool actions (file edits, shell commands, reads) in a single turn without pausing for human verification.
2. **Context Ceiling (< 200k Tokens)**: Keep active session contexts strictly below 200,000 tokens. Never ingest entire repositories, build artifacts, or extensive multi-megabyte log files into an active session.
3. **Fail-Fast Policy**: If an edit or test fails twice with a related stack trace, STOP immediately. Formulate and state a concrete root-cause hypothesis instead of applying speculative trial-and-error patches.
4. **Immediate Context Reset (`/clear`)**: Issue `/clear` the moment a task passes its tests. Carrying stale diffs and shell logs into subsequent tasks pushes context across the 200k boundary into higher-priced token billing tiers.
5. **Open Tab Context Limit**: Maintain no more than 1 or 2 open editor tabs during active sessions to avoid silent context bloat.

### Two-Phase Testing Lifecycle

To reconcile fast developer iteration and token context limits with the CAGE full-gate verification invariant:
- **Inner Loop (Active Turn)**: Target only the isolated unit test (`uv run pytest tests/<path>::<test_name> -v`) during iterative editing turns. This keeps shell buffer outputs compact, avoids cache eviction, and prevents context escalation past 200k tokens.
- **Gate Phase (Pre-Completion & PR)**: Once the isolated test passes, execute the full-suite gate (`make test-fast`) before declaring the task complete or opening a PR.

### Strict Cache-Invariance Rules

Prompt caching provides up to a 90% discount on cache reads, but incurs a 25% surcharge on cache writes:
- **Byte-for-Byte Prefix Stability**: Never inject dynamic timestamps (e.g., current time, ISO dates), randomized session IDs, or volatile environment paths into system prompts, plans, or file headers. Prompt prefixes must remain byte-for-byte identical across turns.
- **5-Minute TTL Window**: Keep turn cycles compact and interactive to maintain cache warmness within the 5-minute TTL window, ensuring Cache Read tokens account for 80%+ of total input volume.
- **Code Standards**: Always write complete, production-ready code with full error handling. Never omit logic with `# TODO` or placeholder shims.

For the complete end-to-end setup guide, IDE shortcuts, Vertex AI ADC credentials, and GCP billing alerts, see [`docs/operations/AGENT_COST_GUARDRAILS.md`](docs/operations/AGENT_COST_GUARDRAILS.md).

