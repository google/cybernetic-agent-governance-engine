# Contributing to Cybernetic Governance Engine

Thank you for contributing. This document describes the Git workflow, branch naming conventions, commit message standards, and pull request process for this project.

---

## Table of Contents

1. [Quick Setup](#quick-setup)
2. [Branch Naming Conventions](#branch-naming-conventions)
3. [Commit Message Standard](#commit-message-standard)
4. [Pull Request Process](#pull-request-process)
5. [Merge Strategy](#merge-strategy)
6. [Release & Tagging Process](#release--tagging-process)
7. [Protected Branches](#protected-branches)
8. [Container Image Builds](#container-image-builds)

---

## Quick Setup

After cloning, run the hook installer to enforce commit standards locally:

```bash
bash scripts/setup_git_hooks.sh
```

This installs:
- A **commit message template** (`.gitmessage`) shown in your editor on every `git commit`
- A **commit-msg hook** that rejects non-Conventional-Commits messages
- A **pre-push hook** that blocks direct pushes to `main` and `rc-v0.1.0`

---

## Branch Naming Conventions

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

**Rules:**
- Use lowercase kebab-case only — no underscores, no uppercase
- Keep descriptions short (≤ 30 chars after the prefix)
- Delete branches after merge

---

## Commit Message Standard

This project follows [Conventional Commits v1.0.0](https://www.conventionalcommits.org/).

### Format

```
<type>(<scope>): <short summary>

[optional body]

[optional footer(s)]
```

### Types

| Type | When to use |
|---|---|
| `feat` | A new feature visible to users or operators |
| `fix` | A bug fix |
| `docs` | Documentation only |
| `style` | Formatting, whitespace — no logic change |
| `refactor` | Code restructuring — no feature or fix |
| `perf` | Performance improvement |
| `test` | Adding or correcting tests |
| `chore` | Build system, dependency updates |
| `ci` | CI/CD pipeline changes |
| `revert` | Reverts a previous commit |

### Scopes

Use one of: `gateway`, `compliance`, `infra`, `governance`, `tests`, `docs`, `ci`, `agentsight`, `advisor`, `nemo`, `opa`

### Rules

- Subject line ≤ 72 characters
- Use imperative mood: "add", not "added" or "adds"
- No period at end of subject line
- Separate subject from body with a blank line
- Body explains **what** and **why**, not how
- Breaking changes: add `BREAKING CHANGE:` in footer or `!` after type

### Examples

```
feat(gateway): add Redis-backed rate limiter for OPA policy calls

Implements token-bucket rate limiting at the gateway layer to prevent
OPA from being overwhelmed during burst traffic. Limit is configurable
via GOVERNANCE_THRESHOLDS_PATH.

Closes #42
```

```
fix(compliance): correct OSCAL component UUID collision on re-export

UUIDs were regenerated on every export, breaking idempotency checks
in the Lula validation pipeline. Now uses deterministic UUID v5
derived from component name + system identifier.
```

```
chore(ci): pin actions/checkout to SHA for supply-chain hardening

BREAKING CHANGE: Workflow callers must update their local cache.
```

---

## Pull Request Process

1. **Branch** from the current integration branch (`rc-v<next>` or `main`)
2. **Commit** using Conventional Commits (the hook enforces this)
3. **Push** your branch and open a PR against the integration branch
4. **Fill in** the PR template completely
5. **Ensure CI passes** — all checks must be green before merge
6. **Request review** from at least one maintainer
7. **Squash-merge** — use "Squash and merge" so each PR becomes one clean commit on the integration branch

### PR Title

The PR title becomes the squash-merge commit message. It must follow Conventional Commits format:

```
feat(gateway): add Redis rate limiter
```

---

## Merge Strategy

| Scenario | Strategy |
|---|---|
| Feature / fix PR → integration branch | **Squash merge** |
| Integration branch → `main` (release) | **Merge commit** (preserves release boundary) |
| Hotfix → `main` + integration branch | **Cherry-pick** |

**Never force-push to `main` or `rc-v*` branches.**

---

## Release & Tagging Process

1. Freeze the integration branch (`rc-v<version>`)
2. Update `CHANGELOG.md` — add release date under the version header
3. Create an **annotated tag**:
   ```bash
   git tag -a v0.1.0 -m "release: v0.1.0 — Cybernetic Governance Engine GA"
   git push origin v0.1.0
   ```
4. Merge the integration branch into `main` via merge commit
5. Create a GitHub Release from the tag, copying the CHANGELOG section as the body

### Tag Format

```
v<MAJOR>.<MINOR>.<PATCH>[-<pre-release>]
```

Examples: `v0.1.0`, `v0.1.0-rc.1`, `v2.1.0-dev.1`

---

## Protected Branches

| Branch | Protection |
|---|---|
| `main` | No direct push; requires PR + CI green + 1 review |
| `rc-v*` | No direct push; requires PR + CI green |

The local pre-push hook enforces this for `main` and the current integration branch. GitHub branch protection rules enforce it server-side.

---

## Container Image Builds

This repo uses **two complementary build paths**. Understanding which to use prevents accidental cache poisoning, missing SHA tags, or broken GCP Console triggers.

### Path A — Per-service `cloudbuild.*.yaml` (GCP Console triggers, event-driven)

| File | Service | GCP trigger |
|---|---|---|
| [`cloudbuild.compliance.yaml`](cloudbuild.compliance.yaml) | `compliance-bridge` | `compliance-bridge-main` — fires on every push to `main` |
| [`cloudbuild.ui.yaml`](cloudbuild.ui.yaml) | `agentsight-ui` | Create a trigger pointing at this file if needed |

These files are the **canonical build specification** for their service. They are designed to be attached to GCP Cloud Build triggers and run under a dedicated least-privilege service account (e.g. `compliance-bridge-sa@<project>.iam.gserviceaccount.com`).

Every per-service file enforces:
- `--no-cache` — prevents stale Docker layer cache from masking dependency changes
- Dual tagging: `:latest` **and** `:<SHORT_SHA>` — `:latest` is mutable convenience; the SHA tag is the immutable, audit-traceable reference required by NIST RMF and ISO 42001
- `--all-tags` push — both tags are pushed atomically
- `machineType: E2_HIGHCPU_8` — consistent build performance
- `timeout: 1200s` — 20-minute ceiling prevents runaway builds
- `logging: CLOUD_LOGGING_ONLY` — structured log routing to Cloud Logging

**When to use:** Rebuilding a single service after a targeted change, or when a GCP trigger fires automatically on `main` push.

```bash
# Rebuild compliance-bridge manually (uses the live GCP trigger config):
gcloud builds submit --config=cloudbuild.compliance.yaml \
  --project=<PROJECT_ID> .

# Rebuild agentsight-ui manually:
gcloud builds submit --config=cloudbuild.ui.yaml \
  --project=<PROJECT_ID> .
```

### Path B — `scripts/build_images.sh` (full-stack fan-out, pre-deploy)

[`scripts/build_images.sh`](scripts/build_images.sh) builds **all six services in parallel** using ephemeral inline Cloud Build configs that mirror the same standards as Path A (`--no-cache`, dual SHA/latest tags, `E2_HIGHCPU_8`, 20-minute timeout). It captures the short git SHA from `git rev-parse --short HEAD` and passes it as the immutable tag.

[`deploy_all.sh`](deploy_all.sh) calls this script automatically as a pre-build step before every `gcloud-gke` Terraform apply, ensuring images exist before Kubernetes deployments reference them.

**When to use:** Full-stack deploys, CI pre-deploy steps, or when you need all services rebuilt from a clean state.

```bash
export PROJECT_ID=<your-gcp-project>
bash scripts/build_images.sh
```

### Which path takes precedence?

They are **not in conflict** — they serve different scopes:

| Concern | Path A (per-service yaml) | Path B (build_images.sh) |
|---|---|---|
| Trigger | GCP Console push trigger | Developer / `deploy_all.sh` |
| Scope | One service | All services |
| Service account | Dedicated least-privilege SA | Caller's identity / Cloud Build default SA |
| SHA source | Cloud Build `$SHORT_SHA` built-in | `git rev-parse --short HEAD` |
| Use case | Automated CD on `main` push | Full-stack pre-deploy fan-out |

### Adding a new service

1. Create `src/<service>/Dockerfile` with the repo root as build context.
2. Add a `build_image "<service>" "src/<service>/Dockerfile" "."` call in [`scripts/build_images.sh`](scripts/build_images.sh).
3. If the service needs an independent GCP Console trigger, create `cloudbuild.<service>.yaml` following the pattern in [`cloudbuild.compliance.yaml`](cloudbuild.compliance.yaml) and register the trigger in GCP Console.
