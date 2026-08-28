# AGENTS.md — Contributor & AI-Agent Standards

> **Reference architecture — deployable and live-testable.** CAGE demonstrates
> governance patterns for AI systems. The codebase is fully deployable to a
> real GKE cluster (dev or prod), and live GKE testing is supported and
> expected — this is not a paper design. The "reference architecture" framing
> means the governance, compliance, and region-guard patterns below are
> illustrative models for adopters to adapt to their own environments, not
> that the system is restricted to local or simulated execution. Deployment,
> change-management, and region-guard rules below describe how to operate a
> live instance of CAGE; they are illustrative patterns for adopters, not
> mandatory production obligations imposed on this repository's maintainers.
>
> **No production deployments to maintain — breaking changes preferred.** This
> repository has no production installations under its management. Backward
> compatibility with hypothetical adopter deployments is not a design constraint.
> When a change can either add a compatibility layer or break cleanly and
> simplify, prefer the breaking change. See [Backward Compatibility Posture](#backward-compatibility-posture)
> for details.

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
12. [Dormant Rules — Reactivate When CAGE Begins Real Deployments](#dormant-rules--reactivate-when-cage-begins-real-deployments)

---

## Commit Message Standard

This project follows [Conventional Commits v1.0.0](https://www.conventionalcommits.org/).
Full detail (examples, self-validation checklist) lives in
[`CONTRIBUTING.md`](CONTRIBUTING.md#commit-message-standard). Summary:

**Format:** `<type>(<scope>): <short summary>` — subject line ≤ 72 characters.

**Types (exactly these 10):** `feat` | `fix` | `docs` | `style` | `refactor` |
`perf` | `test` | `chore` | `ci` | `revert`

**Scopes (use at most one):** `gateway` | `compliance` | `infra` | `governance` |
`tests` | `docs` | `ci` | `agentsight` | `advisor` | `nemo` | `opa`

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
| Release candidate | `rc-v<semver>` | `rc-v3.0.0` |
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

When running tests in parallel with `pytest-xdist` (`-n auto`), always launch
the test suite with `--dist=loadfile` to ensure proper test file isolation across workers.

Correct:
```bash
uv run pytest
uv run pytest tests/ -m "local or unit" -n auto --dist=loadfile --tb=short
uv run pytest tests/test_tls_enforcement.py -v
uv run pytest --cov=src --cov-report=term-missing
uv run python proof/model.py
```

Incorrect (do not suggest):
```bash
pytest
python -m pytest
pytest -n auto  # Missing --dist=loadfile and uv run prefix
python proof/model.py
```

This applies to all agents, contributors, and CI documentation examples.

**Note for Autonomous Agents (Sandbox Execution):**
When running `uv run ...` as an AI agent inside a restricted terminal sandbox, the command may fail with `zsh:1: operation not permitted: uv` (exit code 127). This occurs because `uv` is installed globally on the host machine (e.g. `/opt/homebrew/bin/uv`) and falls outside the sandbox's permitted path boundaries. When you encounter this, do not switch to a different test runner like `python3 -m pytest`; instead, configure your tool call to bypass the sandbox (e.g. `BypassSandbox: true`) so that the command can execute natively in the user's host environment and access the `uv` executable.

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

1. **license-check** — missing Apache 2.0 header in a new `src/` file.
2. **stpa-freshness-check** — STPA source changed without regenerating
   artifacts. Fix: run `scripts/check_stpa_freshness.py`.
3. **langfuse-posture-check** — run `scripts/verify_langfuse_posture.py`.
4. **pytest** — address the failing test before suggesting any workaround.
5. **security-scan** — rotate the credential; never suggest suppressing the scan.

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

### Backward Compatibility Posture

CAGE is a reference architecture with no production installations under this repository's management. Backward compatibility with hypothetical adopter deployments is **not a design constraint**.

**Breaking changes are preferred when they simplify.** When a change can either:
- **(a)** Add a compatibility layer, dual-write path, deprecation window, or version-negotiation shim to preserve backward compatibility, or
- **(b)** Break cleanly and simplify the code, removing dead paths and making behavior more obvious

**Always prefer (b).**

Agents and contributors should not preserve backward compatibility purely to avoid breaking hypothetical downstream adopters. This repository is a living reference design, and clean, simple, correct code takes priority over API stability.

**Breaking changes must still be documented.** Use the Conventional Commits `!` marker and `BREAKING CHANGE:` footer (both required together), and document the change in [`docs/BREAKING_CHANGES_v3.md`](docs/BREAKING_CHANGES_v3.md) so adopters can track migration paths between reference versions.

**This preference is unconditional.** There is no carve-out for any category of change. A previously recognised data-at-rest exception is currently dormant — see [Dormant Rules — Reactivate When CAGE Begins Real Deployments](#dormant-rules--reactivate-when-cage-begins-real-deployments) — and must not be enforced or cited as grounds for deferring a migration.

### Release Versioning

- Releases follow SemVer (`MAJOR.MINOR.PATCH`).
- Release branches: `rc-v<X.Y.Z>` branched from `main`; feature freeze applies
  immediately on branch creation.
- Stable tags are annotated: `git tag -a v<X.Y.Z> -m "release: v<X.Y.Z> — ..."`.
- Regional gates (US_FED, EU_ECB, APAC_MAS) are additive — they block regional
  deployment posture only, never the global stable tag.

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
uv run pytest tests/ -m "local or unit" -n auto --dist=loadfile --tb=short
```
Always launch the test suite with `--dist=loadfile` to ensure proper test file isolation across workers.

### Targeted Test Commands Reference

| Scope / Purpose | Canonical Command |
|---|---|
| **Single test file** | `uv run pytest tests/test_tls_enforcement.py -v` |
| **Specific test method** | `uv run pytest tests/test_tls_enforcement.py::TestTlsProtocolStandards::test_default_client_context_minimum_version -v` |
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
| **Langfuse posture validation** | `uv run python scripts/verify_langfuse_posture.py --dry-run --posture development` |

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

### Nightly CI Without Live GKE

**Verdict: No new nightly workflow is needed.**

- The `local`/`unit` marker subset (~90%+ of the 2553 passing tests) already runs on every push/PR via the existing `pytest-logic` job in all three region postures (`.github/workflows/ci.yml` lines 87–134). A dedicated nightly run of the same markers adds negligible incremental regression-detection value over what is already gated on `main` before merge.
- Tests that genuinely require live GKE (live OPA policy evaluation, Langfuse SLA timing, CMEK/pod-restart checks, real backend accuracy) **cannot be replaced** by a mock-only nightly — these are the `integration`-marked corpus and the 51 skips in the full run.
- Existing CI already covers what a nightly would target: `pytest-logic` (mock/unit, every push), `ai600-unit-tests` (red-team mock, every push), `locust-load-test` (nightly load test).
- **Practical guidance**: treat `pytest-logic` + `ai600-unit-tests` (GKE-independent, secret-free) as the authoritative daily regression gate. Reserve the live-GKE `integration-smoke` job and manual full-suite runs (`port_forward_dev.sh` + `uv run pytest tests/ --run-integration`) for periodic live-service validation.

---

## Dormant Rules — Reactivate When CAGE Begins Real Deployments

**The rules in this section are currently INACTIVE and must not be enforced.**
They were deactivated because CAGE has no deployed instances and therefore no
artifacts at rest — there is no persisted evidence whose verification could be
broken. They are preserved here verbatim, not deleted, so they can be moved
back into the active sections unchanged once CAGE begins operating real
deployments with persisted evidence.

**Instruction to agents:** do not apply these rules when reviewing, writing, or
refusing changes. Do not cite them as a reason to add a compatibility layer, to
defer a migration, or to block a PR. If a contributor cites one of these rules,
note that it is dormant and point them to this section.

Each dormant rule below is recorded as a `### [DORMANT] ...` subsection.
Future deactivated rules should be appended here in the same form.

---

### [DORMANT] Data-at-Rest Read-Compatibility Exception

**Status:** Dormant — not binding. Do not enforce.

**Reactivation trigger:** Reinstate this rule verbatim into the active
[Backward Compatibility Posture](#backward-compatibility-posture) section (and,
if desired, the top introductory blockquote) at the moment CAGE begins
operating real deployments that produce persisted hash chains, signed evidence
records, or stored audit logs which must remain verifiable across releases.
Until such artifacts exist at rest, the rule protects nothing.

**Originally located in:** `### Backward Compatibility Posture`, under
`## Architecture & Design Standards` — immediately after the "Breaking changes
must still be documented." paragraph.

**Verbatim preserved text (paste back unchanged on reactivation):**

> **One exception: data already at rest.** Persisted artifacts like hash chains, signed evidence records, and stored audit logs cannot be invalidated casually — breaking their verification logic breaks trust rather than just breaking an API. When cryptographic or serialization changes affect stored data, preserve read-compatibility for existing artifacts. Example: the RFC 8785 JCS migration deliberately left 10 `json.dumps(sort_keys=True)` sites unmigrated to preserve verification of pre-existing evidence (tracked as POAM-2026-060 in [`docs/POAM.md`](docs/POAM.md)).

**Originally located in:** the top introductory blockquote ("No production
deployments to maintain — breaking changes preferred"), as a closing
qualification on the breaking-changes-preferred posture.

**Verbatim preserved text (paste back unchanged on reactivation):**

> The single exception is **data already at rest** (hash chains, signed evidence records, stored audit logs), where read-compatibility for existing artifacts must be preserved.

**Code decisions to revisit on reactivation.** This exception previously
justified specific implementation choices. When the rule becomes binding again,
re-examine at minimum:

- The WORM-bucket KMS signing path in [`src/gateway/governance/uca_logger.py`](src/gateway/governance/uca_logger.py)
- The evidence hash-chain canonicalization in [`src/compliance_bridge/evidence_stream.py`](src/compliance_bridge/evidence_stream.py)
- The evidence hash-chain canonicalization in [`src/compliance_bridge/context_accumulator.py`](src/compliance_bridge/context_accumulator.py)

**Status of the preserved example (informational — the quoted text above is
frozen verbatim and must not be edited).** The example inside the first
preserved block is now historical: it describes 10 `json.dumps(sort_keys=True)`
sites left unmigrated under POAM-2026-060. Two things have since changed. The
site count was never accurate — the real figure was roughly 25 executable call
sites. And the migration is now complete: all three modules listed above were
migrated to RFC 8785 JCS with **no compatibility shim**, and POAM-2026-060 is
closed. Records written before that migration are not verifiable by the current
code. On reactivation, the quoted text should be pasted back unchanged as the
governing rule, but its illustrative example no longer describes the codebase —
see [`docs/POAM.md`](docs/POAM.md) and
[`docs/BREAKING_CHANGES_v3.md`](docs/BREAKING_CHANGES_v3.md) for the current
state.
