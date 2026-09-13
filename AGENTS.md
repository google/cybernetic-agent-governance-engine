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
- Active IaC lives under `infra/`; `deployment/terraform/` is historical reference only.

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

**Never suggest disabling or skipping a CI check as a fix.**

---

## Compliance Artifact Obligations

- **NIST SP 800-53 control changes**: An OSCAL component update in `compliance/oscal/` is required within 2 business days of PR merge.
- **Kubernetes resources**: Update Lula validations in `compliance/lula/` when adding or removing resources referenced by Lula assertion files.
- **POAM remediations**: Update [`docs/POAM.md`](docs/POAM.md) with: commit SHA, Lula result, closure date.
- **STPA source modifications**: Regenerate STPA artifacts before committing (`uv run python scripts/check_stpa_freshness.py`).

---

## Architecture & Design Standards

### Core Principle: Clean Architecture Over Operational Continuity
CAGE is an illustrative reference architecture. The optimization target is clean code structure, modularity, and architectural clarity. Breaking changes are acceptable and desirable when they remove legacy baggage. Always choose structural clarity.

### The Three-Layer Architecture (Kernel vs. Domain Plugins vs. Rails)

| Layer | Path | Role & Responsibilities | Invariants & Boundary Rules |
|---|---|---|---|
| **Layer 1: Kernel** | `src/gateway/` | **STERA Admissibility Engine**, core governance dispatch loop, standing assembly, consensus engine, CBF engine, evidence accumulator, routing, audit rails. | **Strictly domain-agnostic and vendor-neutral.** Must NEVER import from `src/cage_*` (Layer 2), `src/compliance_bridge/` (Layer 3), or `src/governed_financial_advisor/` (Layer 4). Must NOT import vendor SDKs (`google.cloud`, `boto3`, `azure`, `langfuse`). Enforced in CI by Gate G3 (`scripts/check_import_boundaries.py`). |
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

### Pytest Marker Contract (fail-closed)
Every collected test must carry at least one selection marker (`local`, `unit`, `integration`, `live_external`, `partner_integration`, `chaos`, `load`). Unmarked tests abort collection in CI via `tests/conftest.py`. Default for hermetic tests: `pytestmark = [pytest.mark.unit, pytest.mark.local]`.

### Live GKE Cluster & Staging Runbooks
> **Live Cluster Testing:** For staging port-forwarding, GKE tunnel concurrency rules, and POAM-024 validation, refer to [`docs/operations/GKE_TEST_RUNBOOK.md`](docs/operations/GKE_TEST_RUNBOOK.md).

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
