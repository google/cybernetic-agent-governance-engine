# AGENTS.md — Contributor & AI-Agent Standards

> **Reference architecture only.** CAGE demonstrates governance patterns for
> AI systems; it is not deployed to production. Deployment, change-management,
> and region-guard rules below are illustrative patterns for adopters, not
> operational obligations for this repository.

This file defines standards for anyone (human or AI coding agent) contributing
to this repository. It is written in the tool-agnostic `AGENTS.md` convention
supported by most AI coding assistants. Tool-specific configuration (e.g. Roo
mode routing) lives under `.roo/` and simply points back here — see
[Tool-Specific Configuration](#tool-specific-configuration) at the bottom.

## Table of Contents

1. [Commit Message Standard](#commit-message-standard)
2. [Branch Naming & Merge Strategy](#branch-naming--merge-strategy)
3. [Code Standards](#code-standards)
4. [Deployment Rules](#deployment-rules)
5. [Debugging Standards](#debugging-standards)
6. [Compliance Artifact Obligations](#compliance-artifact-obligations)
7. [Architecture & Design Standards](#architecture--design-standards)
8. [Answering Questions About This Repository](#answering-questions-about-this-repository)
9. [Tool-Specific Configuration](#tool-specific-configuration)

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

### Shared-Module Cross-Region Impact

The following modules deploy simultaneously to all three regional postures
(`US_FED`, `EU_ECB`, `APAC_MAS`):

- `src/gateway/governance/`
- `src/compliance_bridge/`
- `config/compliance/`
- `config/thresholds/`
- `config/oscal/`

For any change to these paths, call out in the PR description:
1. Impact on US_FED posture (NIST SP 800-53)
2. Impact on EU_ECB posture (GDPR / EU AI Act / DORA)
3. Impact on APAC_MAS posture (MAS FEAT / MAS Notice 655 / MAS TRM)
4. `CAGE_DEPLOYMENT_REGION` guard placement for any new data path

### Release Versioning

- Releases follow SemVer (`MAJOR.MINOR.PATCH`).
- Release branches: `rc-v<X.Y.Z>` branched from `main`; feature freeze applies
  immediately on branch creation.
- Stable tags are annotated: `git tag -a v<X.Y.Z> -m "release: v<X.Y.Z> — ..."`.
- Regional gates (US_FED, EU_ECB, APAC_MAS) are additive — they block regional
  deployment posture only, never the global stable tag.

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

When explaining compliance posture or security controls:
- Distinguish clearly between universal gates (ISO 42001) and regional gates
  (US_FED / EU_ECB / APAC_MAS); regional gates block regional deployment only.
- `CAGE_DEPLOYMENT_REGION` guards are required for any new data path in
  shared modules (see [Architecture & Design Standards](#architecture--design-standards)).
- CAGE is a reference architecture — clarify that region gates and deployment
  promotion rules are illustrative patterns, not operational obligations for
  this repository.

When asked about secrets or credentials:
- Never provide example values that resemble real credentials.
- Direct to `terraform.auto.tfvars` for secret storage.
- Note that `secretKeyRef` / `secretRef` is required in Kubernetes manifests.

---

## Tool-Specific Configuration

This file is the single source of truth for agent/contributor standards,
following the tool-agnostic `AGENTS.md` convention. Some AI coding assistants
additionally support mode-specific instruction routing; where used, those
configurations point back to this file rather than duplicating its content:

| Tool | Location | Purpose |
|---|---|---|
| Roo Code | `.roo/rules/`, `.roo/rules-<mode>/` | Per-mode (Code/Debug/Ask/Architect) instruction routing; each file is a thin pointer into the relevant section(s) of this document. |

If you use a different AI coding assistant that supports a project-instructions
file (e.g. a tool reading `CLAUDE.md`, `.cursorrules`, or
`.github/copilot-instructions.md`), point it at this file rather than
introducing a parallel, divergent copy of these standards.
