# CAGE Project Analysis — Structured Summary

**Scope:** `CONTRIBUTING.md`, `.github/workflows/license_guard.yml`,
`scripts/setup_git_hooks.sh`, `compliance/oscal/` directory,
`deployment/k8s/K8S_SECURITY_HARDENING.md`, `.github/workflows/ci.yml`,
`compliance/oscal/system-security-plan.yaml`

**Produced:** 2026-06-05

---

## 1. Contribution Workflow and Governance Model

The project enforces a **trunk-based, PR-gated workflow** with two protected
integration surfaces: `main` (production) and `rc-v<semver>` release candidates.
The governance model is layered — local enforcement via Git hooks, server-side
enforcement via GitHub branch protection rules, and CI enforcement via required
status checks — so no single layer is a single point of failure.

**Branch taxonomy** is strictly typed: `feat/`, `fix/`, `docs/`, `refactor/`,
`ci/`, `hotfix/<version>-<desc>`, `rc-v<semver>`, and `spike/` prefixes are
defined, with kebab-case and a 30-character description cap. This taxonomy mirrors
the commit type vocabulary, creating a coherent naming contract from branch to
commit to PR title to squash-merge commit on the integration branch.

**Merge strategy** is deliberately differentiated by context:
- Squash-merge for feature/fix PRs (clean linear history on integration branches)
- Merge commit for integration-to-`main` promotions (preserves release boundary)
- Cherry-pick for hotfixes (surgical propagation)

Force-push to `main` or `rc-v*` is explicitly prohibited at both the hook and
server-side protection levels.

**Release process** is annotated-tag-driven with a `CHANGELOG.md` update gate
before tagging, ensuring the tag message and GitHub Release body are always
synchronized. Tags follow `v<MAJOR>.<MINOR>.<PATCH>[-<pre-release>]` semver.

**Notable gap:** `CONTRIBUTING.md` references a PR template ("fill in the PR
template completely") but no `.github/pull_request_template.md` is present in
the repository, suggesting the template is missing or not yet committed.

---

## 2. CI/CD Pipeline Design and Enforcement Mechanisms

The `ci.yml` pipeline triggers on pushes to `rc-v2.0.0` and `feature/**`
branches, and on PRs targeting `rc-v2.0.0`. It runs **four parallel jobs**, each
independently scoped:

| Job | Mechanism | Notable Design |
|---|---|---|
| `license-check` | Shell `grep` over `src/` for Apache 2.0 headers | Covers `.py`, `.js`, `.ts`, `.tsx`; exits 1 on first missing header |
| `pytest-logic` | `uv run pytest tests/ -m local` | Dummy env vars for all external services; no live dependencies |
| `stpa-freshness-check` | `scripts/check_stpa_freshness.py` | Validates generated STPA artifacts are current — enforces compiler discipline |
| `langfuse-posture-check` | `scripts/verify_langfuse_posture.py --dry-run` | Validates Langfuse configuration posture without a live instance |

The pipeline uses `astral-sh/setup-uv@v5` for dependency management, consistent
with the project's `uv`-based toolchain. Python version is sourced from
`pyproject.toml` rather than hardcoded, ensuring CI Python version tracks the
project manifest.

**Design pattern — Hermetic CI:** All jobs use mock/dummy credentials and
`--dry-run` flags, making the pipeline fully runnable without any live
infrastructure. This is a deliberate "hermetic CI" design that enables fast,
reliable feedback on every push.

**Relationship to `license_guard.yml`:** The `license_guard.yml` workflow is a
separate, more rigorous license check that runs only on `main`, `rc-v2.0.0`, and
`release/**` branches. It uses `pip-licenses` to generate a full dependency
license JSON and grep-blocks GPL/AGPL/LGPL. This is architecturally distinct from
the header check in `ci.yml` — one checks source file headers, the other checks
transitive dependency licenses. Together they form a two-layer license compliance
fence with different trigger scopes.

**Notable gaps:**
- `scripts/check_stpa_freshness.py` and `scripts/verify_langfuse_posture.py` are
  referenced in CI but not present in the workspace file listing — they may be
  missing, renamed, or not yet committed.
- No automated network policy testing (netassert/Kyverno) is integrated into CI
  despite being documented in `K8S_SECURITY_HARDENING.md`.

---

## 3. License Compliance Strategy

The project implements a **dual-layer license compliance architecture**:

**Layer 1 — Source header enforcement** (`ci.yml`): Every `.py`, `.js`, `.ts`,
and `.tsx` file under `src/` must contain either `"Apache License"` or
`"Copyright 2026"`. This runs on every push to feature branches and PRs, catching
violations early. The `scripts/patch_license.py` script provides automated
header-patching to remediate violations in bulk.

**Layer 2 — Dependency license audit** (`license_guard.yml`): Uses `pip-licenses`
to enumerate all installed package licenses and blocks any GPL, AGPL, or LGPL
dependency. This runs only on protected branches (`main`, `rc-v*`, `release/**`),
acting as a gate before code reaches production-candidate state.

**Design decision:** The separation of these two checks into different workflows
with different trigger scopes is intentional — fast header checks run on every
branch, while the heavier dependency audit runs only at integration boundaries.
This balances developer feedback speed against thoroughness.

**Notable gap:** The dependency audit only covers Python packages (via
`pip-licenses`). The project has a TypeScript frontend (`src/agentsight-ui/`) with
its own `package.json` dependency tree; no equivalent `npm audit` or
`license-checker` step is present for the Node.js dependency graph.

---

## 4. Git Hook Configuration and Developer Tooling

`scripts/setup_git_hooks.sh` installs two hooks and one template via a single
idempotent script:

**Commit message template** (`.gitmessage`): Displayed in the editor on every
`git commit`, providing inline documentation of the type/scope/summary format with
examples. This is a low-friction nudge rather than enforcement.

**`commit-msg` hook**: Enforces the Conventional Commits regex
`^(feat|fix|docs|style|refactor|perf|test|chore|ci|revert)(\([a-z0-9/_-]+\))?(!)?: .{1,72}$`
against the subject line. Merge commits are explicitly exempted. Exceeding 72
characters produces a warning rather than a hard failure — a deliberate choice to
avoid blocking legitimate long summaries while still signaling the convention.

**`pre-push` hook**: Blocks direct pushes to `main` and `rc-v2.0.0` by checking
`git symbolic-ref HEAD`. This is a local mirror of the server-side branch
protection rules, catching the error before the push reaches GitHub.

**Design pattern:** The hooks are written as heredocs inside the setup script,
making them self-contained and version-controlled without requiring a separate hook
management framework (e.g., Husky or pre-commit). The tradeoff is that hook
updates require re-running the setup script manually.

**Notable gap:** The setup script is not automatically invoked (e.g., via a
`Makefile` target or `post-checkout` hook). Developers must know to run it after
cloning. `CONTRIBUTING.md` documents this, but there is no enforcement that it has
been run.

---

## 5. Kubernetes Security Hardening Posture

`deployment/k8s/K8S_SECURITY_HARDENING.md` documents a **NIST SP 800-53 Rev 5
remediation** targeting four controls: SC-7 (Boundary Protection), SC-39 (Process
Isolation), AC-4 (Information Flow Enforcement), and SI-3 (Malicious Code
Protection).

**Pod Security Standards (PSA)** replace the deprecated `PodSecurityPolicy`
controller. The `governance-stack` namespace enforces the `restricted` PSS profile
(the most stringent), while `langfuse` and `vllm` namespaces enforce `baseline`
with `restricted` audit/warn — a pragmatic tiering that acknowledges third-party
workload constraints (CUDA GPU drivers for vLLM) while tracking violations via
audit events.

**Container security context** requirements are comprehensive:
- Pod level: `runAsNonRoot: true`, `runAsUser/Group: 1000`, `fsGroup: 1000`,
  `seccompProfile: RuntimeDefault`
- Container level: `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem:
  true`, `capabilities drop ALL`
- The `readOnlyRootFilesystem` requirement necessitates `emptyDir` volumes for
  `/tmp`, which is explicitly documented with rollback procedures.

**NetworkPolicy topology** implements a **default-deny-all** baseline (both
ingress and egress) with explicit allowlists per workload. The hardening layer
adds six additional policies on top of the nine-policy baseline, for a total of
15 policies. The topology is precisely documented as a communication matrix,
making the intended security posture auditable. A notable design decision: the
standalone OTel Collector egress policy was removed (deprecated 2026-05-31) as
OTLP now exports directly to Langfuse, reducing the attack surface.

**Evidence artifacts** are explicitly called out for each control, with `kubectl`
commands that produce the evidence — this is compliance-as-code thinking applied
to operational verification.

**Notable gaps:**
- mTLS between intra-cluster services is absent (tracked as POAM-013);
  NetworkPolicy is the primary compensating control.
- The `vllm` namespace requires a POAM exception for GPU driver host-level device
  access, which conflicts with the `restricted` PSS profile.
- Automated network policy testing (netassert/Kyverno) is documented but not
  integrated into CI.

---

## 6. OSCAL-Based Compliance Architecture

`compliance/oscal/system-security-plan.yaml` is a machine-readable OSCAL 1.0.4
SSP for a **HIGH-impact system** (FIPS 199: Confidentiality=Moderate,
Integrity=High, Availability=High) in PRE-AUTHORIZATION DRAFT status. The document
is structurally complete but has TBD placeholders for all named parties (System
Owner, AO, ISSO, System Admin, Assessor), indicating it is not yet ready for ATO
submission.

**Control implementation coverage** spans 11 implemented requirements across
AC-2, AC-3, AU-2, AU-12, CM-6, IA-5, IR-1, IR-6, RA-5, SC-8, and SA-11.
Implementation statuses are honest: AC-2, IA-5, IR-6, RA-5, and SC-8 are
`partially-implemented`, each with explicit POAM references (POAM-001, POAM-010,
POAM-013, POAM-014). This reflects a mature compliance posture — the SSP documents
gaps rather than overclaiming.

**STPA-to-OSCAL integration** is the most architecturally distinctive feature:
the SA-11 control implementation documents `src/gateway/governance/stpa_compiler.py`
as a design-time safety control that translates STAMP/STPA Unsafe Control Actions
(UCAs) directly into runtime-enforceable OPA Rego policies, NeMo Colang rails, and
Python validators. Nine UCAs are encoded, covering six hazards across three safety
constraints. This eliminates the "Natural Language Tax" — the gap between
human-readable safety specs and running code — and is a novel compliance
architecture pattern not commonly seen in OSCAL SSPs.

**Component inventory** maps seven software/service components (CAGE Gateway,
NeMo Guardrails, OPA, Compliance Bridge, AgentSight eBPF Monitor, Langfuse, GKE)
to seven inventory items, with responsible roles assigned per component. GKE/GCP
is modeled as a `leveraged-authorization` component inheriting FedRAMP High
controls for PE/MP/MA/PS families.

**Lula integration**: Four Lula validation manifests are referenced (AC-3, AU-12,
CM-6, RA-5), enabling automated compliance-as-code assertion against the SSP. The
`compliance/oscal/` directory contains a full OSCAL artifact suite:

| File | Purpose |
|---|---|
| `system-security-plan.yaml` | Primary SSP (this document) |
| `component-definition.yaml` | ISO 42001 AIMS component definitions |
| `information-type-registry.yaml` | NIST SP 800-60 information type mappings |
| `sp800053-profile.yaml` | CAGE-tailored SP 800-53 HIGH baseline profile |
| `common-controls-catalog.yaml` | GKE/GCP inherited controls catalog |
| `stpa_compiler_ssp_patch.yaml` | STPA compiler SSP patch (SA-11 evidence) |
| `sp800-53-component-definition.yaml` | SP 800-53 component definitions |

**Notable gaps:**
- Langfuse Data Processing Agreement (DPA) is TBD (POAM-TBD), blocking ATO for
  the external interconnection.
- All named party fields are TBD placeholders — must be populated before ATO
  submission.
- The SSP version string `1.0.0-draft+stpa+stpa` contains a duplicated `+stpa`
  build metadata segment, suggesting a minor tooling artifact in the STPA compiler
  SSP patch merge.

---

## Cross-Cutting Patterns and Relationships

| Pattern | Where it appears |
|---|---|
| **Compliance-as-code** | Lula manifests validate OSCAL controls; STPA compiler generates enforceable artifacts; `kubectl` evidence commands in K8S doc |
| **Hermetic testing** | CI uses dummy credentials; `--dry-run` flags; `pytest -m local` marker |
| **Layered enforcement** | Git hooks → GitHub branch protection → CI required checks (three independent layers) |
| **Dual-layer license compliance** | Header check (every branch) + dependency audit (protected branches only) |
| **POAM-driven gap tracking** | Every partially-implemented control references a specific POAM item |
| **Evidence artifact specification** | K8S hardening doc and SSP both specify exact commands/artifacts that produce compliance evidence |
| **Type-scoped naming contract** | Branch names, commit types, PR titles, and OSCAL component scopes all use the same vocabulary |
