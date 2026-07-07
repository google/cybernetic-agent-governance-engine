# OSS Readiness Plan — Cybernetic Governance Engine (CAGE)

**Prepared:** 2026-07-07  
**Analyst:** Roo (Architect mode)  
**Target release:** Apache 2.0 public open-source

---

## Executive Summary

The CAGE repository is in **good structural shape** for an open-source release but has a focused set of blockers that must be resolved before the repository is safe to publish. The six areas of concern, in descending severity:

1. **Internal identity leakage (HIGH)** — The GCP project ID `YOUR_GCP_PROJECT_ID`, the GitHub username `lahlfors`, and the developer's local filesystem path `/Users/larsahlfors/` appear in 66+ locations across Markdown docs, YAML deployment manifests, Terraform files, and two scripts. These are the most urgent items because they expose the author's personal identity and internal GCP project name.

2. **`scripts/fix_mcp_configs.py` (HIGH)** — This developer-utility script contains absolute paths to the developer's local macOS home directory (`/Users/larsahlfors/Library/...`, `/Users/larsahlfors/.gemini/...`). It has no business being in a public repository and must be deleted or replaced with a generic template.

3. **`scripts/patch_license.py` bug (MEDIUM)** — The `HEADER` constant in this script contains a duplicated `# limitations under the License.` line (lines 30–31). Every file patched by this script will carry a malformed header. The script must be fixed before it is run again.

4. **`deployment/` and `compliance/` YAML files (MEDIUM)** — Kubernetes manifests, Cloud Build configs, and compliance audit evidence files contain hardcoded `gcr.io/YOUR_GCP_PROJECT_ID/` image references, `YOUR_GCP_PROJECT_ID` GCP project IDs, and GCS bucket names. These must be parameterised before public release.

5. **`CONTRIBUTING.md` gaps (LOW-MEDIUM)** — The file covers Git workflow and CI well but is missing: dev environment setup instructions, code style/linting guidance, and a CLA/DCO statement — all standard requirements for a public OSS project.

6. **`README.md` internal cluster reference (LOW)** — Line 21 names the internal GKE cluster `gke_YOUR_GCP_PROJECT_ID_us-central1-a_cage-dev`. This must be replaced with a generic placeholder.

**License headers in `src/`:** All `.py`, `.ts`, `.tsx`, and `.js` files under `src/` already carry the correct Apache 2.0 `Copyright 2026 Google LLC` header. The `patch_license.py` script has already been run successfully. No missing-header remediation is needed for `src/`.

**LICENSE file:** Present and correct — full Apache 2.0 text, no modifications.

**`third_party/` directory:** No vendored third-party source code was found inside `src/`. The `proof/model.py` file (adapted from LalaSkye/no-direct-bind) is already documented in `NOTICE`. The `src/agentsight-ui/src/protos/gateway.js` and `gateway.ts` files are hand-authored TypeScript type stubs, not generated protobuf output — no third-party attribution needed.

---

## 1. README.md — Current State & Required Changes

### Current State

`README.md` is a comprehensive, 583-line document covering:
- Project description and feature list ✅
- Architecture overview with ASCII diagram ✅
- Compliance framework table ✅
- Quick Start with prerequisites and environment variables ✅
- Project structure tree ✅
- Documentation index ✅
- Dependencies table with licenses ✅
- License declaration ✅

### Required Changes

| # | Location | Issue | Fix |
|---|----------|-------|-----|
| R-01 | Line 21 | `gke_YOUR_GCP_PROJECT_ID_us-central1-a_cage-dev` — internal cluster name exposed | Replace with: `Tests run against a live GKE cluster. See infra/DEPLOYMENT_GUIDE.md for cluster setup.` |
| R-02 | Line 364 | `git clone https://github.com/lahlfors/cybernetic-governance-engine.git` — personal GitHub username | Replace `lahlfors` with the canonical org/username chosen for the public release (e.g. `google` or the chosen org slug) |
| R-03 | Line 49 | `> **For PA Lead reviewers:**` — internal Google PA (Privacy Assessment) process reference | Remove or rewrite as a generic note about Kubernetes extension classification |
| R-04 | Lines 302, 45 | `.clinerules §12.4` — internal tool reference | Replace with a link to the actual source file or remove the parenthetical |
| R-05 | General | No `SECURITY.md` link or vulnerability disclosure instructions | Add a "Security" section pointing to `SECURITY.md` (to be created) with responsible disclosure instructions |
| R-06 | General | No "Contributing" section linking to `CONTRIBUTING.md` | Add a one-line "Contributing" section at the bottom |

### What Is Already Good

- The "This is not an officially supported Google product" disclaimer is present (line 580) ✅
- Apache 2.0 license declaration is present ✅
- The ATO-not-yet-issued warning is prominent ✅

---

## 2. LICENSE File — Current State & Required Changes

### Current State

`LICENSE` contains the complete, unmodified Apache License Version 2.0 text (203 lines). The file is correct.

### Required Changes

None. The `LICENSE` file is complete and correct.

**Note:** The `NOTICE` file is also present and correctly attributes:
- LalaSkye/no-direct-bind (Apache 2.0, adapted into `proof/model.py`)
- NVIDIA NeMo Guardrails (Apache 2.0, external dependency)
- LangChain-core, LangGraph (MIT, external dependencies)
- Microsoft Presidio (MIT, external dependency)
- LiteLLM (MIT, external dependency)

One minor issue: `NOTICE` still lists `Outlines` (Apache 2.0) as a dependency even though `README.md` line 522 states it was removed in v0.1.0 due to CVE-2025-69872. The `Outlines` entry should be removed from `NOTICE`.

---

## 3. CONTRIBUTING.md — Current State & Required Changes

### Current State

`CONTRIBUTING.md` (253 lines) covers:
- Git hook setup ✅
- Branch naming conventions ✅
- Conventional Commits standard ✅
- Pull request process ✅
- Merge strategy ✅
- Release & tagging process ✅
- Protected branches ✅
- Container image build paths (Cloud Build) ✅

### Missing Sections

| # | Missing Section | Why Required |
|---|-----------------|--------------|
| C-01 | **Dev environment setup** | Contributors need to know: Python version requirements (≥3.10, <3.13), `uv` installation, `uv sync --group dev`, how to run tests locally (`bash setup_test_env.sh && python -m pytest tests/`), and Docker Compose for infrastructure |
| C-02 | **Code style / linting** | No mention of linters, formatters, or type checkers. The project uses `eslint` (agentsight-ui) and presumably `ruff`/`mypy` for Python. Contributors need to know what `pre-commit` checks will block their PR |
| C-03 | **CLA / DCO statement** | Required for any Google-affiliated OSS project. Must state whether contributors must sign a CLA (Google CLA) or use DCO (`Signed-off-by:` in commits). Without this, contributions cannot be legally accepted |
| C-04 | **Issue reporting / bug reports** | No guidance on how to file issues, what information to include, or how to report security vulnerabilities (must point to `SECURITY.md`) |
| C-05 | **Code of Conduct** | Standard for public OSS. Should reference or include a `CODE_OF_CONDUCT.md` (Contributor Covenant is the Google standard) |
| C-06 | **First-time contributor guide** | "Good first issue" label guidance, where to ask questions (Discussions vs Issues) |

### Internal References to Remove

- Line 199: `cloudbuild.compliance.yaml` references `compliance-bridge-main` GCP trigger — acceptable as documentation context, but should note this is GCP-specific and optional
- Lines 214–229: `gcloud builds submit --project=<PROJECT_ID>` — already uses `<PROJECT_ID>` placeholder ✅

---

## 4. License Headers — Audit & Remediation Plan

### Audit Results

**`src/` directory — `.py` files:** All 183 Python files found with `Copyright 2026 Google LLC` header. **Zero files missing headers.**

**`src/` directory — `.ts` files:** All 4 TypeScript files carry the correct `/* Copyright 2026 Google LLC */` block comment header.

**`src/` directory — `.tsx` files:** All 3 TSX files carry the correct header.

**`src/` directory — `.js` files:** Both JS files (`eslint.config.js`, `src/protos/gateway.js`) carry the correct header.

**Conclusion: No source files under `src/` are missing license headers.**

### Known Bug in `scripts/patch_license.py`

The `HEADER` constant in [`scripts/patch_license.py`](scripts/patch_license.py) has a **duplicated line**:

```python
# Line 30:  # See the License for the specific language governing permissions and
# Line 31:  # limitations under the License.
# Line 32:  # limitations under the License.   ← DUPLICATE
```

This means any file patched by this script in the future will carry a malformed 14-line header instead of the correct 13-line header. The script must be fixed before it is run again.

**Fix:** Remove the duplicate `# limitations under the License.` at line 31 of `scripts/patch_license.py`.

### Files Outside `src/` That May Need Headers

The CI license-check job (per global standards) only enforces headers for `*.py`, `*.js`, `*.ts`, `*.tsx` files under `src/`. However, the following files outside `src/` are Python source files that lack headers and may be flagged by stricter linters:

| File | Status |
|------|--------|
| `scripts/patch_license.py` | ✅ Has header |
| `scripts/fix_mcp_configs.py` | ❌ No header — but this file should be **deleted** (see Section 6) |
| `examples/chaos_agent_playground.py` | Needs verification |
| `examples/governance_demo.py` | Needs verification |
| `tests/*.py` | Needs verification — CI enforces `src/` only |
| `proof/model.py` | Needs verification — adapted from third-party, special attribution needed |

**Recommendation:** Run `python scripts/patch_license.py` (after fixing the duplicate line bug) to catch any remaining files in `tests/` and `deployment/` that are missing headers.

---

## 5. third_party/ Directory — Audit & Plan

### Current State

There is **no `third_party/` directory** in the repository. No vendored/bundled third-party source code was found inside `src/`.

### Findings

| File | Nature | Action Required |
|------|--------|-----------------|
| `proof/model.py` | Adapted from LalaSkye/no-direct-bind (Apache 2.0) | Already documented in `NOTICE`. Move to `third_party/no-direct-bind/` with its own `LICENSE` file and a `README` explaining the adaptation. |
| `src/agentsight-ui/src/protos/gateway.js` | Hand-authored TypeScript stub (18 lines, `export {};`) | Not vendored. No action needed. |
| `src/agentsight-ui/src/protos/gateway.ts` | Hand-authored TypeScript type definitions | Not vendored. No action needed. |
| `src/gateway/protos/gateway_pb2.py` | protobuf-generated Python | Generated from `gateway.proto` — not third-party source. Add to `.gitignore` or keep with a `# Generated file` comment. |
| `src/gateway/protos/nemo_pb2.py` | protobuf-generated Python | Same as above. |
| `src/gateway/protos/gateway_pb2_grpc.py` | protobuf-generated Python | Same as above. |
| `src/gateway/protos/nemo_pb2_grpc.py` | protobuf-generated Python | Same as above. |

### Recommended `third_party/` Structure

```
third_party/
└── no-direct-bind/
    ├── LICENSE          # Apache 2.0 — copy from upstream
    ├── README.md        # Explains: original source URL, commit SHA, what was adapted
    └── (no source files needed — adaptation is in proof/model.py)
```

The `NOTICE` file already contains the correct attribution. Creating the `third_party/` directory with a `LICENSE` file makes the attribution machine-readable and follows Google OSS conventions.

---

## 6. Scrubbing Internal/Confidential Content — Audit & Plan

### 6.1 Internal GCP Project ID: `YOUR_GCP_PROJECT_ID`

**Severity: HIGH** — This is a real GCP project ID that identifies the author's personal/internal GCP project.

**Locations found (23 YAML files + 10 Markdown files):**

| File | Line(s) | Pattern |
|------|---------|---------|
| `deployment/k8s/gateway.yaml` | 22, 25, 42 | `gcr.io/YOUR_GCP_PROJECT_ID/gateway:latest`, `GOOGLE_CLOUD_PROJECT: "YOUR_GCP_PROJECT_ID"` |
| `deployment/k8s/backend-deployment.yaml` | 44, 47, 57 | Same pattern |
| `deployment/k8s/compliance-bridge.yaml` | 43, 46, 144 | Same pattern |
| `deployment/k8s/financial-advisor.yaml` | 45, 48, 95–103 | Same pattern + GCS model paths |
| `deployment/k8s/nemo.yaml` | 39, 42 | Same pattern |
| `deployment/k8s/vllm-inference-spot.yaml` | 103, 106 | Same pattern |
| `deployment/k8s/service-account.yaml` | 21 | `financial-advisor-sa@YOUR_GCP_PROJECT_ID.iam.gserviceaccount.com` |
| `deployment/k8s/security-scan-cronjob.yaml` | 49 | `gcr.io/YOUR_GCP_PROJECT_ID/gateway:latest` |
| `deployment/k8s/sbom-cronjob.yaml` | 361 | `GCP_PROJECT_ID: "YOUR_GCP_PROJECT_ID"` |
| `deployment/k8s/lula-cron.yaml` | 192, 195, 319 | Same pattern |
| `deployment/k8s/gcp/ingress-gke.yaml` | 15 | DNS zone reference |
| `deployment/docker/cloudbuild.advisor.yaml` | 31 | `_GCP_PROJECT_ID: "YOUR_GCP_PROJECT_ID"` |
| `deployment/docker/cloudbuild.nemo.yaml` | 31 | Same |
| `deployment/docker/cloudbuild.lula.yaml` | 4, 11, 16 | Artifact Registry path |
| `compliance/audits/compliance-trigger-evidence.yaml` | 8–11 | Full GCP resource names |
| `infra/targets/gcp-gke/main.tf` | 200 | Comment referencing SA email |
| `deployment/update_langfuse_secret.py` | 215 | `langfuse-instance-YOUR_GCP_PROJECT_ID` |
| `README.md` | 21 | Cluster name |
| `docs/operations/RELEASE_RUNBOOK.md` | 5–6, 192, 260, 315–320, 361, 507–593 | Multiple references |
| `docs/operations/DEPLOYMENT_EXECUTION_PLAN_US_FED_DEV.md` | 6, 40, 66, 79, 109, 167–218 | Multiple references |
| `docs/technical-report/08-DEPLOYMENT-INFRASTRUCTURE.md` | 179–219 | Image references + cluster name |
| `docs/technical-report/09-OPERATIONAL-RUNBOOK.md` | 736 | Cluster name |
| `docs/technical-report/01-SYSTEM-OVERVIEW.md` | 85 | Cluster name |
| `docs/project/RELEASE_PLAN.md` | 322, 679–814 | Multiple references |
| `docs/compliance/us_fed/PHASE4_LULA_VALIDATION_PLAN.md` | 8–61 | Multiple references |
| `CHANGELOG.md` | 224 | SA email |

**Fix strategy:**
1. In all Kubernetes manifests and Cloud Build configs: replace `gcr.io/YOUR_GCP_PROJECT_ID/` with `${IMAGE_REGISTRY}/` (already partially done with comments in some files) and `YOUR_GCP_PROJECT_ID` project ID with `${GCP_PROJECT_ID}` substitution variable.
2. In all Markdown documentation: replace specific cluster/project names with generic placeholders like `<your-gcp-project>`, `<your-cluster-name>`, or `your-project-id`.
3. `compliance/audits/compliance-trigger-evidence.yaml`: This file contains a real Cloud Build trigger resource name and service account. **Delete this file** — it is internal operational evidence, not needed in a public repo.

### 6.2 Personal Username: `lahlfors` / `larsahlfors`

**Severity: HIGH** — Personal GitHub username and local filesystem paths.

| File | Line(s) | Pattern | Fix |
|------|---------|---------|-----|
| `README.md` | 364 | `github.com/lahlfors/cybernetic-governance-engine` | Replace with canonical org URL |
| `CHANGELOG.md` | 238–239 | `github.com/lahlfors/cybernetic-governance-engine` | Replace with canonical org URL |
| `scripts/fix_mcp_configs.py` | 6–13 | `/Users/larsahlfors/Library/...`, `/Users/larsahlfors/.gemini/...` | **Delete this file entirely** |
| `docs/operations/RELEASE_RUNBOOK.md` | 192, 225, 243, 297, 507, 520, 560, 578, 593, 613 | `/Users/larsahlfors/Code/cybernetic-governance-engine` | Replace with `<repo-root>` or remove the `cd` commands |
| `docs/project/RELEASE_PLAN.md` | 679, 710, 787 | Same local path | Same fix |
| `plans/markdown-audit-remediation.md` | 45–63 | `file:///Users/larsahlfors/Code/...` absolute URIs | Replace with relative paths (already documented in the plan itself) |

### 6.3 Internal Operational Documents

The following documents contain internal operational details (cluster credentials, deployment procedures with real resource names) that are inappropriate for a public repository:

| File | Issue | Recommendation |
|------|-------|----------------|
| `docs/operations/RELEASE_RUNBOOK.md` | Contains `git filter-repo` commands with real paths, real cluster contexts, real project IDs | Sanitize: replace all real values with `<placeholder>` variables |
| `docs/operations/DEPLOYMENT_EXECUTION_PLAN_US_FED_DEV.md` | Contains real GCP project, cluster, bucket names throughout | Sanitize or move to `docs/internal/` (gitignored) |
| `docs/project/RELEASE_PLAN.md` | Contains `git filter-repo` commands with real local paths | Sanitize |
| `compliance/audits/compliance-trigger-evidence.yaml` | Real Cloud Build trigger resource name, real SA email | **Delete** |
| `docs/operations/DEPLOYMENT_FIX_REPORT_2026Q2.md` | Real cluster name, real image SHA | Sanitize cluster/project references |

### 6.4 `deployment/update_langfuse_secret.py`

Line 215 contains `langfuse-instance-YOUR_GCP_PROJECT_ID` as a hardcoded fallback. Replace with `langfuse-instance-<project-id>` or read from an environment variable.

### 6.5 Hardcoded GCS Model Paths

Several Kubernetes manifests hardcode GCS paths like `gs://YOUR_GCP_PROJECT_ID-models/models--Qwen--...`. These expose the internal GCS bucket name and specific model snapshot SHA. Replace with environment variable references:

```yaml
# Before:
value: "gs://YOUR_GCP_PROJECT_ID-models/models--Qwen--Qwen2.5-7B-Instruct/snapshots/a09a35..."
# After:
valueFrom:
  configMapKeyRef:
    name: model-config
    key: MODEL_FAST_PATH
```

Or at minimum replace with `${MODEL_FAST_PATH}` substitution variables.

### 6.6 No Hardcoded Credentials Found

The search for `pk-lf-*`, `sk-lf-*`, `hf_*`, `GOOG*`, and `password = "..."` patterns in Python source files returned **zero results**. The `.env.example` file correctly uses `<YOUR_*>` placeholders for all secrets. The `CAGE_ROUTING_SEAL_SECRET=dev-only-insecure-placeholder-not-for-production-use` in `.env.example` is intentionally documented as a dev-only placeholder — this is acceptable.

---

## 7. Implementation Sequence

The following tasks are ordered by dependency and severity. All implementation work should be done in Code mode.

```
Phase 1 — Blockers (must complete before any public push)
Phase 2 — Required (complete before announcing the release)
Phase 3 — Polish (complete before or shortly after release)
```

### Phase 1 — Blockers

| # | Task | Files | Mode |
|---|------|-------|------|
| 1.1 | **Delete `scripts/fix_mcp_configs.py`** — contains developer's personal macOS paths | `scripts/fix_mcp_configs.py` | Code |
| 1.2 | **Delete `compliance/audits/compliance-trigger-evidence.yaml`** — contains real GCP resource names and SA email | `compliance/audits/compliance-trigger-evidence.yaml` | Code |
| 1.3 | **Fix duplicate line in `scripts/patch_license.py`** — remove the second `# limitations under the License.` at line 31 | `scripts/patch_license.py` | Code |
| 1.4 | **Replace `lahlfors` GitHub username in `README.md` and `CHANGELOG.md`** with the canonical public org/username | `README.md` line 364, `CHANGELOG.md` lines 238–239 | Code |
| 1.5 | **Remove internal cluster name from `README.md` line 21** | `README.md` | Code |
| 1.6 | **Remove PA Lead reviewer note from `README.md` line 49** | `README.md` | Code |

### Phase 2 — Required

| # | Task | Files | Mode |
|---|------|-------|------|
| 2.1 | **Parameterise all `gcr.io/YOUR_GCP_PROJECT_ID/` image references** in Kubernetes manifests — replace with `${IMAGE_REGISTRY}/<service>:latest` | All `deployment/k8s/*.yaml` | Code |
| 2.2 | **Replace `YOUR_GCP_PROJECT_ID` GCP project ID** in all K8s manifests and Cloud Build configs with `${GCP_PROJECT_ID}` substitution | `deployment/k8s/*.yaml`, `deployment/docker/cloudbuild.*.yaml` | Code |
| 2.3 | **Replace `gs://YOUR_GCP_PROJECT_ID-models/` GCS paths** in K8s manifests with environment variable references | `deployment/k8s/gateway.yaml`, `financial-advisor.yaml`, `compliance-bridge.yaml` | Code |
| 2.4 | **Sanitize `docs/operations/RELEASE_RUNBOOK.md`** — replace all `/Users/larsahlfors/...` paths and `YOUR_GCP_PROJECT_ID` project references with `<placeholder>` variables | `docs/operations/RELEASE_RUNBOOK.md` | Code |
| 2.5 | **Sanitize `docs/project/RELEASE_PLAN.md`** — same as 2.4 | `docs/project/RELEASE_PLAN.md` | Code |
| 2.6 | **Sanitize `docs/operations/DEPLOYMENT_EXECUTION_PLAN_US_FED_DEV.md`** | `docs/operations/DEPLOYMENT_EXECUTION_PLAN_US_FED_DEV.md` | Code |
| 2.7 | **Fix `deployment/update_langfuse_secret.py` line 215** — replace hardcoded fallback with env var | `deployment/update_langfuse_secret.py` | Code |
| 2.8 | **Remove `Outlines` entry from `NOTICE`** — package was removed in v0.1.0 | `NOTICE` | Code |
| 2.9 | **Add `SECURITY.md`** — responsible disclosure policy, contact email, scope | `SECURITY.md` (new file) | Code |
| 2.10 | **Add `CODE_OF_CONDUCT.md`** — Contributor Covenant v2.1 | `CODE_OF_CONDUCT.md` (new file) | Code |
| 2.11 | **Create `third_party/no-direct-bind/` directory** with `LICENSE` and `README.md` | `third_party/` (new directory) | Code |

### Phase 3 — Polish

| # | Task | Files | Mode |
|---|------|-------|------|
| 3.1 | **Add dev environment setup section to `CONTRIBUTING.md`** — Python version, `uv sync`, test commands | `CONTRIBUTING.md` | Code |
| 3.2 | **Add CLA/DCO statement to `CONTRIBUTING.md`** | `CONTRIBUTING.md` | Code |
| 3.3 | **Add code style section to `CONTRIBUTING.md`** — ruff, mypy, eslint commands | `CONTRIBUTING.md` | Code |
| 3.4 | **Add issue reporting and security disclosure section to `CONTRIBUTING.md`** | `CONTRIBUTING.md` | Code |
| 3.5 | **Add "Contributing" and "Security" sections to `README.md`** | `README.md` | Code |
| 3.6 | **Fix `plans/markdown-audit-remediation.md`** — replace `file:///Users/larsahlfors/...` URIs with relative paths (already documented in the plan) | `plans/markdown-audit-remediation.md` | Code |
| 3.7 | **Verify `proof/model.py` has Apache 2.0 header** and correct third-party attribution comment | `proof/model.py` | Code |
| 3.8 | **Run `python scripts/patch_license.py`** (after fix in 1.3) to catch any remaining files in `tests/`, `examples/`, `deployment/` | All source dirs | Code |
| 3.9 | **Sanitize `docs/technical-report/08-DEPLOYMENT-INFRASTRUCTURE.md`** and `09-OPERATIONAL-RUNBOOK.md` | `docs/technical-report/` | Code |
| 3.10 | **Sanitize `docs/compliance/us_fed/PHASE4_LULA_VALIDATION_PLAN.md`** | `docs/compliance/us_fed/` | Code |

---

## 8. Cross Linter Readiness

The CI pipeline (`.github/workflows/security-scan.yml`) runs pip-audit, Trivy, Grype, and CycloneDX SBOM. The following additional checks are expected when the repo is submitted to Google's OSS cross-linter or equivalent tooling:

### Expected Warnings and Resolutions

| Check | Expected Warning | Resolution |
|-------|-----------------|------------|
| **License header check** | Will pass for all `src/` files. May flag `tests/`, `examples/`, `proof/` | Run `patch_license.py` (after fix) on those directories |
| **Secret scanning** | `CAGE_ROUTING_SEAL_SECRET=dev-only-insecure-placeholder...` in `.env.example` | This is intentional and documented. Add to allowlist / `.trivyignore` with a comment |
| **Dependency license check** | `fakeredis` is BSD-3-Clause — compatible with Apache 2.0 | No action needed |
| **Dependency license check** | `google-adk` is Apache 2.0 | No action needed |
| **Binary / generated file check** | `src/gateway/protos/gateway_pb2.py`, `nemo_pb2.py`, `gateway_pb2_grpc.py`, `nemo_pb2_grpc.py` are protobuf-generated | Add `# Generated by protoc` comment at top; consider adding to `.gitignore` and generating at build time |
| **Internal URL check** | `YOUR_GCP_PROJECT_ID` references in `deployment/` and `docs/` | Resolved by Phase 1 and Phase 2 tasks above |
| **CLA check** | No CLA bot configured | Add Google CLA bot to `.github/` or configure DCO enforcement |
| **NOTICE file check** | `Outlines` listed but removed from dependencies | Remove from `NOTICE` (task 2.8) |
| **`patch_license.py` duplicate line** | Malformed header if script is re-run | Fix duplicate line (task 1.3) |

### Recommended Additional CI Checks to Add

```yaml
# Add to .github/workflows/ci.yml:
- name: Check for internal references
  run: |
    if grep -r "YOUR_GCP_PROJECT_ID\|lahlfors\|larsahlfors\|/Users/lars" \
      --include="*.py" --include="*.ts" --include="*.tsx" --include="*.js" \
      --include="*.yaml" --include="*.md" src/ deployment/ docs/ scripts/; then
      echo "ERROR: Internal references found"
      exit 1
    fi

- name: Verify license headers
  run: python scripts/patch_license.py --check  # Add --check flag to script