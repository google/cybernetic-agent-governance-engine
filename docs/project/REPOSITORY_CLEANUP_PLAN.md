# Repository Cleanup Plan — CAGE / Cybernetic Governance Engine

**Prepared:** 2026-06-14  
**Scope:** Full repository audit of `/Users/larsahlfors/Code/cybernetic-governance-engine`  
**Status:** Recommendation only — no files have been moved or deleted

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Root-Level Clutter](#2-root-level-clutter)
3. [Duplicate & Conflicting Files](#3-duplicate--conflicting-files)
4. [Misplaced Files](#4-misplaced-files)
5. [Redundant Directories](#5-redundant-directories)
6. [Test Directory Disorganisation](#6-test-directory-disorganisation)
7. [Documentation Sprawl](#7-documentation-sprawl)
8. [Deployment Directory Issues](#8-deployment-directory-issues)
9. [Source Code Structure Issues](#9-source-code-structure-issues)
10. [Naming Inconsistencies](#10-naming-inconsistencies)
11. [Files to Archive or Delete](#11-files-to-archive-or-delete)
12. [Proposed Target Directory Hierarchy](#12-proposed-target-directory-hierarchy)
13. [Prioritised Action List](#13-prioritised-action-list)

---

## 1. Executive Summary

The repository has grown organically across multiple sprints and now exhibits several structural problems that impede developer navigation, increase CI maintenance cost, and create compliance audit risk. The most critical issues are:

- **Root-level pollution**: 7+ ad-hoc scripts and 3 versioned audit JSON files sit at the repository root with no clear ownership.
- **Duplicate deployment artefacts**: `deployment/docker/cloudbuild_gateway.yaml` and `deployment/docker/cloudbuild.gateway.yaml` are near-identical files; `deployment/k8s/` and `deployment/k8s_rendered/` contain overlapping template files; `deployment/rebuild_backend.py` and `deployment/scripts/rebuild_backend.py` are duplicates.
- **Ephemeral scratch material committed to main**: The `scratch/` directory contains one-off profiling scripts, raw JSON baselines, and a `docs_summary.txt` that have no place in a production repository.
- **Plans directory is a staging area, not a permanent home**: `plans/` holds six markdown planning documents that belong either in `docs/` or in a closed GitHub issue.
- **Test directory lacks sub-structure**: 70+ test files live flat in `tests/`, with sub-directories (`evaluation/`, `governance/`, `load/`, `red_team/`, `red_teaming/`) that are inconsistently named and partially duplicated.
- **Documentation is split across four locations**: `docs/`, `docs/architecture/`, `docs/technical-report/`, and the root level (`README.md`, `ARCHITECTURE.md`, `COMPLIANCE.md`, `CONTRIBUTING.md`, `README_GOVERNANCE.md`).
- **`proof/` directory is misnamed and nearly empty**: Contains only two files, one of which (`compliance-trigger-evidence.yaml`) is a duplicate of the root-level file of the same name.

---

## 2. Root-Level Clutter

The repository root currently contains **17 files** that do not belong there. A clean root should contain only: `README.md`, `LICENSE`, `NOTICE`, `CHANGELOG.md`, `CONTRIBUTING.md`, `pyproject.toml`, `uv.lock`, `Makefile`, `docker-compose.yml`, `.gitignore`, `.dockerignore`, `.env.example`, `.gitmessage`, `.trivyignore`, and `deploy_all.sh`.

### 2a. Ad-hoc scripts at root — move to `scripts/`

| File | Recommended destination | Reason |
|---|---|---|
| [`fetch_langfuse_metrics.py`](../fetch_langfuse_metrics.py) | `scripts/fetch_langfuse_metrics.py` | Operational script, not a project entry point |
| [`generate_reasoning_manifest.py`](../generate_reasoning_manifest.py) | `scripts/generate_reasoning_manifest.py` | Build-time utility |
| [`get_env.py`](../get_env.py) | `scripts/get_env.py` | Dev-environment helper |
| [`init_antigravity.sh`](../init_antigravity.sh) | `scripts/init_antigravity.sh` | One-time setup script |
| [`setup_dev.sh`](../setup_dev.sh) | `scripts/setup_dev.sh` | Dev-environment setup |
| [`setup_test_env.sh`](../setup_test_env.sh) | `scripts/setup_test_env.sh` | Test-environment setup |
| [`start_port_forwards.sh`](../start_port_forwards.sh) | `scripts/start_port_forwards.sh` | Already duplicated by `scripts/port_forward_dev.sh` — **consolidate then move** |
| [`update_secret.sh`](../update_secret.sh) | `scripts/update_secret.sh` | Operational helper |
| [`verify_all.py`](../verify_all.py) | `scripts/verify_all.py` | Release-gate verification |

### 2b. Versioned audit JSON files at root — move to `compliance/audits/`

| File | Recommended destination | Reason |
|---|---|---|
| [`audit_results.json`](../audit_results.json) | `compliance/audits/audit_results_v1.json` | Rename for clarity; archive in compliance artefacts |
| [`audit_results_v2.json`](../audit_results_v2.json) | `compliance/audits/audit_results_v2.json` | Same |
| [`audit_results_v3.json`](../audit_results_v3.json) | `compliance/audits/audit_results_v3.json` | Same |

These files are compliance evidence. They belong under `compliance/`, not at the root where they are invisible to the audit trail.

### 2c. Misplaced Cloud Build config at root

| File | Recommended destination | Reason |
|---|---|---|
| [`cloudbuild.compliance.yaml`](../cloudbuild.compliance.yaml) | `deployment/docker/cloudbuild.compliance.yaml` | All Cloud Build configs live in `deployment/docker/` |
| [`cloudbuild.ui.yaml`](../cloudbuild.ui.yaml) | `deployment/docker/cloudbuild.ui.yaml` | Same |

### 2d. Misplaced Kubernetes trigger file at root

| File | Recommended destination | Reason |
|---|---|---|
| [`compliance-trigger-evidence.yaml`](../compliance-trigger-evidence.yaml) | `compliance/audits/compliance-trigger-evidence.yaml` | This is a compliance artefact, not a root config |

### 2e. Misplaced README variants at root

| File | Recommended destination | Reason |
|---|---|---|
| [`ARCHITECTURE.md`](../ARCHITECTURE.md) | `docs/ARCHITECTURE.md` | Architecture docs belong in `docs/` |
| [`README_GOVERNANCE.md`](../README_GOVERNANCE.md) | `docs/GOVERNANCE_OVERVIEW.md` | Rename and move; `README_` prefix is non-standard |

### 2f. Misplaced integration test log at root

| File | Recommended destination | Reason |
|---|---|---|
| [`integration_test_results.log`](../integration_test_results.log) | **Delete or add to `.gitignore`** | Generated artefact; should never be committed |

---

## 3. Duplicate & Conflicting Files

### 3a. Cloud Build gateway configs — two files, same purpose

`deployment/docker/cloudbuild_gateway.yaml` and `deployment/docker/cloudbuild.gateway.yaml` both build the gateway image from `src/gateway/Dockerfile` and push to `gcr.io/${_GCP_PROJECT_ID}/gateway:latest`. The only differences are:
- `cloudbuild_gateway.yaml` uses `_GCP_PROJECT_ID: ""` (empty default)
- `cloudbuild.gateway.yaml` uses `_GCP_PROJECT_ID: "YOUR_GCP_PROJECT_ID"` (hardcoded project ID — **a secret hygiene violation per Rule 9.1**)

**Action:** Delete `cloudbuild_gateway.yaml` (the older, underscore-named variant). Keep `cloudbuild.gateway.yaml` but remove the hardcoded project ID, replacing it with `""` or a CI-injected substitution. The `.clinerules` §6.4 designates `cloudbuild_gateway.yaml` as the primary — this designation should be updated to match the surviving file.

### 3b. `rebuild_backend.py` — three copies

| Path | Status |
|---|---|
| [`deployment/rebuild_backend.py`](../deployment/rebuild_backend.py) | Root of `deployment/` |
| [`deployment/scripts/rebuild_backend.py`](../deployment/scripts/rebuild_backend.py) | Inside `deployment/scripts/` |
| [`scripts/`](../scripts/) | No copy here — but `scripts/build_images.sh` overlaps in purpose |

**Action:** Keep one canonical copy at `deployment/scripts/rebuild_backend.py`. Delete `deployment/rebuild_backend.py`. Update any references in `Makefile` or CI.

### 3c. `start_port_forwards.sh` vs `scripts/port_forward_dev.sh`

Both scripts forward local ports to GKE services for development. They serve the same purpose with slightly different port sets.

**Action:** Merge into `scripts/port_forward_dev.sh`, document all ports in comments, delete `start_port_forwards.sh` from root.

### 3d. `deployment/k8s/` vs `deployment/k8s_rendered/` — template duplication

`deployment/k8s_rendered/` contains five `.yaml.tpl` files that are also present in `deployment/k8s/`:

| `k8s_rendered/` file | Duplicate in `k8s/` |
|---|---|
| `backend-deployment.yaml.tpl` | `k8s/backend-deployment.yaml.tpl` |
| `frontend-deployment.yaml.tpl` | `k8s/frontend-deployment.yaml.tpl` |
| `vllm-deployment.yaml.tpl` | `k8s/vllm-deployment.yaml.tpl` |
| `vllm-reasoning.yaml.tpl` | `k8s/vllm-reasoning.yaml.tpl` |
| `vllm-fast.yaml.tpl` | No counterpart — unique to `k8s_rendered/` |

Additionally, `deployment/k8s/generated/` contains rendered outputs of these templates (8 plain YAML files). These generated files should be gitignored, not committed.

**Action:**
1. Delete `deployment/k8s_rendered/` entirely — it is a staging area that leaked into version control.
2. Add `deployment/k8s/generated/` to `.gitignore`.
3. Keep all `.yaml.tpl` source templates in `deployment/k8s/` only.

### 3e. `deployment/k8s/current_deployment.yaml` and `deployment/k8s/live_deployment.yaml`

These are point-in-time snapshots of what was deployed to the cluster. They are not declarative source-of-truth manifests and will drift from reality immediately after any `kubectl apply`.

**Action:** Delete both. The source-of-truth is the `.yaml` and `.yaml.tpl` files in `deployment/k8s/`. If cluster state snapshots are needed for audit, generate them via `kubectl get all -o yaml` and store in `compliance/audits/`, not in `deployment/k8s/`.

### 3f. `proof/compliance-trigger-evidence.yaml` vs root `compliance-trigger-evidence.yaml`

Both files exist. The `proof/` copy appears to be the original; the root copy is a stray duplicate.

**Action:** Keep one copy at `compliance/audits/compliance-trigger-evidence.yaml`. Delete both the root copy and `proof/compliance-trigger-evidence.yaml`, then delete the now-empty `proof/` directory (see §5).

### 3g. `deployment/opa_config.yaml` vs `deployment/k8s/opa.yaml`

`deployment/opa_config.yaml` is an OPA configuration file. `deployment/k8s/opa.yaml` is the Kubernetes manifest that deploys OPA. These are different things but the naming is confusing because `opa_config.yaml` sits at the `deployment/` root while all other K8s-related configs are in `deployment/k8s/`.

**Action:** Move `deployment/opa_config.yaml` → `deployment/k8s/opa-config.yaml` (note the kebab-case rename for consistency with all other files in that directory).

---

## 4. Misplaced Files

### 4a. `deployment/` root — operational scripts that belong in `scripts/`

The `deployment/` directory contains Python scripts and shell utilities that are not deployment manifests or configs:

| File | Recommended destination |
|---|---|
| [`deployment/rebuild_backend.py`](../deployment/rebuild_backend.py) | `deployment/scripts/rebuild_backend.py` (consolidate with existing copy) |
| [`deployment/teardown.py`](../deployment/teardown.py) | `deployment/scripts/teardown.py` |
| [`deployment/update_langfuse_secret.py`](../deployment/update_langfuse_secret.py) | `scripts/update_langfuse_secret.py` (alongside other Langfuse scripts) |
| [`deployment/system_authz.rego`](../deployment/system_authz.rego) | `config/opa/system_authz.rego` — OPA policy belongs with other OPA policies |
| [`deployment/service.yaml`](../deployment/service.yaml) | `deployment/k8s/service.yaml` — K8s manifest belongs in `k8s/` |
| [`deployment/config.yaml`](../deployment/config.yaml) | Needs investigation — likely `config/deployment.yaml` |
| [`deployment/__init__.py`](../deployment/__init__.py) | **Delete** — `deployment/` is not a Python package |

### 4b. `deployment/lib/` — a Python library inside a deployment directory

`deployment/lib/` contains `config.py`, `gcp.py`, and `utils.py` — a small Python utility library used by the deployment scripts. This is a Python package (`__init__.py` present) embedded inside a non-Python directory.

**Action:** Move `deployment/lib/` → `scripts/lib/` so it sits alongside the scripts that consume it. Update all imports in `deployment/scripts/*.py`.

### 4c. `proof/model.py` — a Python source file in a compliance evidence directory

`proof/model.py` is a Python module sitting in a directory named `proof/` that otherwise contains only a YAML evidence file.

**Action:** Determine what `proof/model.py` models. If it is a data model for compliance evidence, move it to `src/compliance_bridge/models.py`. If it is a one-off experiment, move it to `scratch/` before that directory is archived.

### 4d. `src/agentsight-ui/gateway_protos/` — proto files duplicated from `src/gateway/protos/`

`src/agentsight-ui/gateway_protos/` contains `gateway.proto` and `nemo.proto`, which are identical to `src/gateway/protos/gateway.proto` and `src/gateway/protos/nemo.proto`. The UI also has a third copy at `src/agentsight-ui/src/protos/` (compiled JS/TS outputs).

**Action:** Establish a single canonical proto source at `src/gateway/protos/`. The UI's `gateway_protos/` directory should be removed and replaced with a build step that compiles from the canonical source. The compiled `src/agentsight-ui/src/protos/` outputs should be gitignored and regenerated at build time.

### 4e. `config/compliance/` vs `compliance/` — split compliance baseline data

Regional compliance baselines (`US_FED_BASELINE.json`, `EU_ECB_BASELINE.json`, `APAC_MAS_BASELINE.json`) exist in **two** locations:
- `config/compliance/` — runtime config consumed by the application
- `config/thresholds/` — threshold variants of the same baselines

**Action:** This split is intentional (runtime config vs. compliance artefacts) but should be documented clearly in both directories' `README.md` files to prevent confusion. The `config/compliance/reconciliation_worker.py` is a Python module that does not belong in a config directory — move it to `src/compliance_bridge/reconciliation_worker.py`.

---

## 5. Redundant Directories

### 5a. `scratch/` — ephemeral work committed to version control

`scratch/` contains 9 files: one-off profiling scripts, raw latency JSON baselines, a `docs_summary.txt`, and load test scripts. None of these belong in a production repository branch.

| File | Disposition |
|---|---|
| `scratch/docs_summary.txt` | **Delete** — generated summary, no value in VCS |
| `scratch/latency_baseline_v2.0.x.json` | Move to `compliance/audits/perf/` if needed as evidence; otherwise delete |
| `scratch/latency_post_opt_v2.0.x.json` | Same |
| `scratch/generate_test_traces.py` | Move to `tests/evaluation/` if still used; otherwise delete |
| `scratch/inspect_langfuse.py` | Move to `scripts/inspect_langfuse.py` if still used; otherwise delete |
| `scratch/phase3_final_load_test.py` | Move to `tests/load/` if still used; otherwise delete |
| `scratch/profile_latency_baseline.py` | Move to `tests/load/` if still used; otherwise delete |
| `scratch/test_judge.py` | Move to `tests/evaluation/` if still used; otherwise delete |
| `scratch/trade_load_test.py` | Move to `tests/load/` if still used; otherwise delete |

**Action:** Triage each file, relocate anything still useful, then delete `scratch/` entirely. Add `scratch/` to `.gitignore` so it can be used locally without risk of accidental commits.

### 5b. `plans/` — sprint planning documents committed to main

`plans/` contains 6 markdown planning documents:
- `path-b-deployment-plan.md`
- `poam-framework-redesign.md`
- `pre-release-doc-audit-remediation.md`
- `release-readiness-gap-analysis.md`
- `technical-report.md`
- `token-quota-proxy-impl-plan.md`

These are sprint artefacts. Completed plans should be closed as GitHub issues or archived. Active plans belong in GitHub Issues/Projects, not in the repository tree.

**Action:** For each file: if the work is complete, delete it. If the work is ongoing, convert it to a GitHub Issue and delete the file. Move `technical-report.md` to `docs/` if it contains reference material (it appears to be a draft of `docs/technical-report/`). Delete `plans/` once empty.

### 5c. `proof/` — nearly empty, misnamed directory

`proof/` contains only two files:
- `proof/compliance-trigger-evidence.yaml` — duplicate of root-level file (see §3f)
- `proof/model.py` — misplaced Python module (see §4c)

**Action:** Relocate both files as described in §3f and §4c, then delete `proof/`.

### 5d. `examples/evidence/` — empty directory with only a `.gitkeep`

`examples/evidence/.gitkeep` exists solely to preserve an empty directory. The `examples/` directory itself contains only 4 Python files and a README.

**Action:** If `examples/evidence/` is intended to hold generated evidence files, add it to `.gitignore` instead of tracking it with `.gitkeep`. If it is never populated, remove it.

### 5e. `compliance/generated-policies/` — contains only a README

`compliance/generated-policies/README.md` exists but the directory contains no generated policies. This is a placeholder that creates false expectations.

**Action:** Either populate it with the actual generated policies (from `config/opa/generated_stpa_policy.rego`) or remove the directory and update the README that references it.

### 5f. `deployment/k8s/generated/` — generated artefacts committed to VCS

8 rendered YAML files live in `deployment/k8s/generated/`. These are outputs of the template rendering process and will drift from the templates.

**Action:** Add `deployment/k8s/generated/` to `.gitignore`. Add a `make render-manifests` target that regenerates them from the `.yaml.tpl` sources.

---

## 6. Test Directory Disorganisation

The `tests/` directory contains **70+ flat test files** plus 5 inconsistently named sub-directories. This makes it difficult to run targeted test suites and understand test coverage at a glance.

### 6a. Duplicate red-team sub-directories

Both `tests/red_team/` and `tests/red_teaming/` exist:

| Directory | Contents |
|---|---|
| `tests/red_team/` | `adversarial_dataset.json`, `adversarial_red_team.py`, `run_red_team.py` |
| `tests/red_teaming/` | `test_adversarial.py` |

**Action:** Consolidate into `tests/red_team/`. Move `test_adversarial.py` into `tests/red_team/`. Delete `tests/red_teaming/`.

### 6b. `tests/governance/` — only 2 files, inconsistently named

`tests/governance/test_automated_loop.py` and `tests/governance/test_nemo_refinements.py` are isolated in a sub-directory while dozens of governance-related tests (`test_governance_*.py`, `test_symbolic_governor.py`, etc.) live flat in `tests/`.

**Action:** Either move all governance tests into `tests/governance/` for consistency, or dissolve `tests/governance/` and move its two files to the flat `tests/` level. The former is preferred for scalability.

### 6c. Proposed test sub-directory structure

The flat `tests/` layout should be reorganised into logical groups matching the `src/` package structure:

```
tests/
├── conftest.py
├── README.md
├── unit/                    # Fast, no-network tests
│   ├── gateway/             # Tests for src/gateway/
│   ├── compliance_bridge/   # Tests for src/compliance_bridge/
│   └── governed_advisor/    # Tests for src/governed_financial_advisor/
├── integration/             # Tests requiring live services
│   ├── test_compliance_bridge_integration.py
│   ├── test_gateway_connectivity.py
│   └── test_langfuse_smoke.py
├── governance/              # Governance-specific tests
│   ├── test_automated_loop.py
│   ├── test_nemo_refinements.py
│   └── ... (all test_governance_*.py files)
├── evaluation/              # LLM evaluation harnesses
│   ├── agentbeats_sim.py
│   └── evaluator_agent_eval.py
├── load/                    # Locust / load tests
│   └── locustfile.py
├── red_team/                # Adversarial / red-team tests
│   ├── adversarial_dataset.json
│   ├── adversarial_red_team.py
│   ├── run_red_team.py
│   └── test_adversarial.py
└── opa_snapshots/           # OPA policy test fixtures
    ├── 01_no_identity_match.json
    └── 02_trade_no_auth.json
```

### 6d. Sprint-named test files — rename for permanence

`tests/test_sprint2_high_severity.py` and `tests/test_sprint3_medium_severity.py` use sprint numbers as identifiers. Sprint numbers are ephemeral; the tests themselves may be permanent.

**Action:** Rename to describe what they test:
- `test_sprint2_high_severity.py` → `test_security_high_severity.py`
- `test_sprint3_medium_severity.py` → `test_security_medium_severity.py`

Note: `tests/test_security_fixes.py` already exists — review for overlap before renaming.

---

## 7. Documentation Sprawl

Documentation is currently scattered across four locations, making it hard to know where to look for any given topic.

### 7a. Current state — four documentation locations

| Location | File count | Problem |
|---|---|---|
| Repository root | 5 MD files | `ARCHITECTURE.md`, `COMPLIANCE.md`, `CONTRIBUTING.md`, `README_GOVERNANCE.md`, `CHANGELOG.md` — mixed with code artefacts |
| `docs/` | ~45 MD files | Flat — no sub-structure beyond `architecture/` and `technical-report/` |
| `docs/architecture/` | 2 MD files | Under-populated sub-directory |
| `docs/technical-report/` | 11 MD files | Well-structured but isolated |

### 7b. Recommended `docs/` structure

```
docs/
├── README.md                        # Index / navigation guide
├── architecture/                    # System design documents
│   ├── ARCHITECTURE.md              # (moved from root)
│   ├── DUAL_PROJECT_ARCHITECTURE.md
│   ├── EXTENSIBILITY_ARCHITECTURE.md
│   ├── GATEWAY_ARCHITECTURE.md
│   ├── INFERENCE_GATEWAY_ARCHITECTURE.md
│   ├── AGENT_OPS_ARCHITECTURE.md
│   └── NEURO_SYMBOLIC_GOVERNANCE.md
├── compliance/                      # Compliance & regulatory docs
│   ├── ISO_42001_COMPLIANCE.md
│   ├── GOVERNANCE_CROSSWALK.md
│   ├── AUDIT_LOG_SCHEMA.md
│   ├── SYSTEM_DESCRIPTION_ISO_42001.md
│   ├── banking_regs.md              # Rename → BANKING_REGULATIONS.md
│   └── STPA_ANALYSIS.md
├── operations/                      # Runbooks & operational guides
│   ├── DEPLOYMENT_RULES.md
│   ├── DEPLOYMENT_DECISION_RECORD.md
│   ├── DEPLOYMENT_FIX_REPORT_2026Q2.md
│   ├── HOW_TO_DEMO_OBSERVABILITY.md
│   ├── LATENCY_STRATEGY.md
│   ├── MCP_INTEGRATION_GUIDE.md
│   ├── IR_PLAN.md
│   └── SECRET_MANAGEMENT_OPTIONS.md
├── security/                        # Security assessment documents
│   ├── SECURITY_ASSESSMENT_PLAN.md
│   ├── SECURITY_AUDIT_REPORT.md
│   ├── SECURITY_STATUS.md
│   ├── HITL_TOCTOU_REMEDIATION.md
│   └── CAUSAL_AND_CBF_GOVERNANCE.md
├── release/                         # Release planning & runbooks
│   ├── RELEASE_PLAN.md
│   ├── RELEASE_RUNBOOK.md
│   ├── V2_ROADMAP.md
│   └── PHASE4_LULA_VALIDATION_PLAN.md
├── nist-rmf/                        # NIST RMF chunked documents
│   ├── CHUNK1_CURRENT_STATE.md
│   ├── CHUNK2_PREPARE_CATEGORIZE.md
│   ├── CHUNK3_SELECT_IMPLEMENT.md
│   ├── CHUNK4_ASSESS_AUTHORIZE.md
│   └── CHUNK5_MONITOR_ROADMAP.md
├── poam/                            # Plan of Action & Milestones
│   ├── POAM_INDEX.md
│   ├── POAM_ISO42001.md
│   ├── POAM_US_FED.md
│   ├── POAM_EU_ECB.md
│   └── POAM_APAC_MAS.md
├── project/                         # Project management docs
│   ├── ROLES_AND_RESPONSIBILITIES.md
│   ├── CODE_QUALITY_ANALYSIS.md
│   ├── PROJECT_ANALYSIS.md
│   ├── PRODUCTION_READINESS_REPORT.md
│   └── PRESENTATION_PROMPTS.md
└── technical-report/                # Keep as-is (already well-structured)
    ├── README.md
    ├── 01-SYSTEM-OVERVIEW.md
    └── ...
```

### 7c. Specific renames needed in `docs/`

| Current name | Recommended name | Reason |
|---|---|---|
| `docs/banking_regs.md` | `docs/compliance/BANKING_REGULATIONS.md` | Lowercase filename is inconsistent with all other docs |
| `docs/NIST_RMF_CHUNK1_CURRENT_STATE.md` | `docs/nist-rmf/CHUNK1_CURRENT_STATE.md` | Remove redundant `NIST_RMF_` prefix once in sub-directory |
| `docs/POAM.md` | `docs/poam/POAM_MASTER.md` | Distinguish from the index file |
| `docs/CAGE_ONE_PAGER.md` | `docs/project/CAGE_ONE_PAGER.md` | Marketing/overview doc belongs in project/ |
| `docs/financial-advisor.png` | `assets/financial-advisor.png` | Images belong in `assets/`, not `docs/` |

### 7d. Root-level markdown files to move

| File | Move to |
|---|---|
| [`ARCHITECTURE.md`](../ARCHITECTURE.md) | `docs/architecture/ARCHITECTURE.md` |
| [`README_GOVERNANCE.md`](../README_GOVERNANCE.md) | `docs/GOVERNANCE_OVERVIEW.md` |
| [`COMPLIANCE.md`](../COMPLIANCE.md) | `docs/compliance/COMPLIANCE_OVERVIEW.md` |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | Keep at root — standard open-source convention |
| [`CHANGELOG.md`](../CHANGELOG.md) | Keep at root — standard open-source convention |

---

## 8. Deployment Directory Issues

### 8a. `deployment/` root is a mixed bag

The `deployment/` directory mixes Kubernetes manifests, Docker configs, Python scripts, shell scripts, a Python library, and documentation. It needs clear sub-directory separation.

### 8b. Recommended `deployment/` structure

```
deployment/
├── README.md
├── TERRAFORM_MIGRATION.md
├── docker/                          # All Cloud Build & Dockerfile configs
│   ├── cloudbuild.advisor.yaml
│   ├── cloudbuild.compliance.yaml   # (moved from root)
│   ├── cloudbuild.gateway.yaml      # (cloudbuild_gateway.yaml deleted)
│   ├── cloudbuild.lula.yaml
│   ├── cloudbuild.ui.yaml           # (moved from root)
│   ├── cloudbuild.vllm.yaml
│   ├── Dockerfile.lula
│   ├── Dockerfile.lula-multistage
│   ├── Dockerfile.lula-runtime
│   ├── Dockerfile.vllm
│   └── download_config.py
├── k8s/                             # All Kubernetes manifests
│   ├── base/                        # Static manifests (no templating)
│   │   ├── agentsight-daemon.yaml
│   │   ├── cilium-egress-lockdown.yaml
│   │   ├── compliance-bridge.yaml
│   │   ├── financial-advisor.yaml
│   │   ├── gateway.yaml
│   │   ├── gateway-hpa.yaml
│   │   ├── ingress.yaml
│   │   ├── langfuse-db.yaml
│   │   ├── langfuse-web.yaml
│   │   ├── langfuse-worker.yaml
│   │   ├── langfuse-worker-hpa.yaml
│   │   ├── linkerd-mtls-policy.yaml
│   │   ├── lula-cron.yaml
│   │   ├── lula-network-policy.yaml
│   │   ├── lula-rbac.yaml
│   │   ├── minio.yaml
│   │   ├── model-pvc.yaml
│   │   ├── nemo-rails-configmap.yaml
│   │   ├── nemo.yaml
│   │   ├── network-policy.yaml
│   │   ├── network-policy-hardening.yaml
│   │   ├── opa.yaml
│   │   ├── opa-config.yaml          # (renamed from opa_config.yaml)
│   │   ├── oscal-artifact-secrets.yaml
│   │   ├── pod-security-admission.yaml
│   │   ├── redis-config.yaml
│   │   ├── redis-credentials-secret.yaml
│   │   ├── redis-statefulset.yaml
│   │   ├── sbom-cronjob.yaml
│   │   ├── security-context-patch.yaml
│   │   ├── security-scan-cronjob.yaml
│   │   ├── service-account.yaml
│   │   ├── trivy-egress-policy.yaml
│   │   ├── vllm-cross-namespace-services.yaml
│   │   ├── vllm-governance.yaml
│   │   ├── vllm-inference-spot.yaml
│   │   ├── vllm-namespace.yaml
│   │   ├── vllm-pdb.yaml
│   │   ├── vllm-reasoning-pdb.yaml
│   │   ├── vllm-services.yaml
│   │   └── vllm-streaming.yaml
│   ├── templates/                   # Parameterised templates (.yaml.tpl)
│   │   ├── agentsight-ui.yaml.tpl
│   │   ├── backend-deployment.yaml.tpl
│   │   ├── compliance-bridge-deployment.yaml.tpl
│   │   ├── frontend-deployment.yaml.tpl
│   │   ├── gateway-deployment.yaml.tpl
│   │   ├── model-downloader.yaml.tpl
│   │   ├── model-pvc.yaml.tpl
│   │   ├── vllm-deployment.yaml.tpl
│   │   ├── vllm-fast.yaml.tpl
│   │   └── vllm-reasoning.yaml.tpl
│   ├── inference-gateway/           # Keep as-is (already sub-structured)
│   └── docs/
│       ├── K8S_SECURITY_HARDENING.md
│       └── NAMESPACE-GUIDE.md
├── agentsight/                      # Keep as-is
├── dashboard/                       # Keep as-is
├── langfuse/                        # Keep as-is
└── scripts/                         # Deployment-specific scripts
    ├── create_secret_manual.py
    ├── download_config.py
    ├── fix_langsmith.py
    ├── fix_postgresql_imagepullbackoff.sh
    ├── mirror_models.py
    ├── rebuild_backend.py           # Single canonical copy
    ├── recover_advisor.sh
    ├── teardown.py
    ├── update_langfuse_secret.py
    ├── upload_to_gcs.py
    └── lib/                         # (moved from deployment/lib/)
        ├── __init__.py
        ├── config.py
        ├── gcp.py
        └── utils.py
```

### 8c. Files to delete from `deployment/`

| File | Reason |
|---|---|
| `deployment/__init__.py` | `deployment/` is not a Python package |
| `deployment/k8s_rendered/` (entire dir) | Duplicate templates — see §3d |
| `deployment/k8s/generated/` (entire dir) | Generated artefacts — gitignore instead |
| `deployment/k8s/current_deployment.yaml` | Point-in-time snapshot — see §3e |
| `deployment/k8s/live_deployment.yaml` | Point-in-time snapshot — see §3e |
| `deployment/k8s/db-reset.yaml` | One-time operational job — archive or delete |
| `deployment/docker/cloudbuild_gateway.yaml` | Duplicate of `cloudbuild.gateway.yaml` — see §3a |
| `deployment/docker/Dockerfile.lula-multistage` | Verify if superseded by `Dockerfile.lula-runtime` |

---

## 9. Source Code Structure Issues

### 9a. `src/agentsight-ui/` — kebab-case directory name in a Python monorepo

All other `src/` packages use `snake_case` (`compliance_bridge`, `gateway`, `governed_financial_advisor`, `cybernetic_governance_engine`). The UI package uses kebab-case (`agentsight-ui`), which is correct for a Node.js project but inconsistent with the monorepo convention.

**Action:** This is acceptable as-is since it is a Node.js sub-project, but it should be clearly documented in the root `README.md` that `src/agentsight-ui/` is a separate frontend application with its own build toolchain, not a Python package.

### 9b. `src/cybernetic_governance_engine/` — empty package

`src/cybernetic_governance_engine/__init__.py` exists but the directory contains only that one file. This appears to be a namespace placeholder.

**Action:** Either populate it with top-level package exports (re-exporting from `gateway`, `compliance_bridge`, etc.) or remove it if it serves no purpose. An empty package with no exports adds confusion.

### 9c. `src/gateway/slm/` — SLM server files not under `server/`

`src/gateway/slm/mock_slm.py` and `src/gateway/slm/slm_server.py` implement a Small Language Model inference server. The gateway already has a `src/gateway/server/` directory for server implementations.

**Action:** Move `src/gateway/slm/` → `src/gateway/server/slm/` to co-locate all server implementations. Update imports accordingly.

### 9d. `generated_` prefix files committed to source

`src/gateway/governance/generated_saga_nodes.py` and `src/gateway/governance/generated_stpa_validator.py` are prefixed `generated_`, implying they are outputs of a code-generation step. Committing generated files alongside hand-written source creates confusion about what is authoritative.

**Action:** Verify whether these are generated by `scripts/deontic_policy_extractor.py` or `src/gateway/governance/stpa_compiler.py`. If so, add them to `.gitignore` and generate them in CI. If they are hand-maintained despite the prefix, rename them to remove the misleading `generated_` prefix.

### 9e. `src/gateway/governance/safety_params.json` — data file inside a Python package

A JSON config file sitting inside a Python package directory is not importable as Python and is not obviously a config file vs. a test fixture.

**Action:** Move to `config/safety_params.json` alongside other configuration files. Update the loader in [`src/gateway/governance/safety.py`](../src/gateway/governance/safety.py) to read from the config path.

### 9f. `src/governed_financial_advisor/graph/governance/trade_policy.rego` — OPA policy embedded in graph package

An OPA Rego policy file is embedded inside the Python graph package. OPA policies are managed separately via `config/opa/` and `deployment/k8s/opa.yaml`.

**Action:** Move to `config/opa/trade_policy.rego`. Update the OPA client in [`src/governed_financial_advisor/infrastructure/governance_client.py`](../src/governed_financial_advisor/infrastructure/governance_client.py) to load from the config path.

### 9g. `src/governed_financial_advisor/agents/explainer/` — missing `__init__.py`

`src/governed_financial_advisor/agents/explainer/agent.py` exists but there is no `__init__.py` in the `explainer/` directory, unlike all sibling agent packages (`data_analyst/`, `evaluator/`, `execution_analyst/`, `financial_advisor/`, `governed_trader/`, `risk_analyst/`).

**Action:** Add `src/governed_financial_advisor/agents/explainer/__init__.py`.

### 9h. Root-level Dockerfiles — four files with no clear ownership

The repository root contains four Dockerfiles:
- [`Dockerfile`](../Dockerfile) — appears to be the main gateway/backend image
- [`Dockerfile.nemo`](../Dockerfile.nemo) — NeMo Guardrails image
- [`Dockerfile.slm`](../Dockerfile.slm) — SLM inference image
- [`Dockerfile.vllm`](../Dockerfile.vllm) — vLLM image (also exists at `deployment/docker/Dockerfile.vllm`)

**Action:**
- Verify whether root `Dockerfile` duplicates `src/gateway/Dockerfile`; if so, delete the root copy
- Move `Dockerfile.nemo` → `deployment/docker/Dockerfile.nemo`
- Move `Dockerfile.slm` → `deployment/docker/Dockerfile.slm`
- Delete root `Dockerfile.vllm` (duplicate of `deployment/docker/Dockerfile.vllm`)
- Update all Cloud Build configs and `docker-compose.yml` to reference new paths

---

## 10. Naming Inconsistencies

### 10a. Cloud Build file naming — two conventions in use

| Convention | Files using it |
|---|---|
| `cloudbuild.{service}.yaml` (dot-separated) | `cloudbuild.advisor.yaml`, `cloudbuild.gateway.yaml`, `cloudbuild.lula.yaml`, `cloudbuild.vllm.yaml` |
| `cloudbuild_{service}.yaml` (underscore) | `cloudbuild_gateway.yaml` — the duplicate being deleted (§3a) |

**Action:** Standardise on `cloudbuild.{service}.yaml`. The underscore variant is already being deleted.

### 10b. Kubernetes manifest naming — mixed conventions

| Convention | Examples |
|---|---|
| `{service}.yaml` | `gateway.yaml`, `nemo.yaml`, `minio.yaml` |
| `{service}-{resource}.yaml` | `gateway-hpa.yaml`, `langfuse-worker-hpa.yaml` |
| `{service}-deployment.yaml` | `compliance-bridge.yaml` (no `-deployment` suffix) vs `backend-deployment.yaml.tpl` |

**Action:** Standardise on `{service}-{resource-type}.yaml` where the resource type is omitted only when the file contains a single obvious resource. Document the convention in `deployment/k8s/docs/NAMESPACE-GUIDE.md`.

### 10c. `POAM.md` vs `POAM_INDEX.md` — ambiguous master document

`docs/POAM.md` and `docs/POAM_INDEX.md` both exist. It is unclear which is the master document and which is the index.

**Action:** Rename `POAM.md` → `POAM_MASTER.md` to distinguish it from the index. Move both into `docs/poam/` (see §7b).

### 10d. `README_GOVERNANCE.md` — non-standard README naming

The `README_` prefix is not a standard convention. This file is a governance overview document, not a README for a specific directory.

**Action:** Rename to `docs/GOVERNANCE_OVERVIEW.md` (see §7d).

### 10e. `docker-compose.yml` vs `docker-compose.agentsight.yaml` — mixed extensions

`docker-compose.yml` and `docker-compose.dev.yml` use `.yml` (three-letter). `deployment/agentsight/docker-compose.agentsight.yaml` uses `.yaml` (four-letter).

**Action:** Standardise all Docker Compose files on `.yaml`. Rename:
- `docker-compose.yml` → `docker-compose.yaml`
- `docker-compose.dev.yml` → `docker-compose.dev.yaml`

### 10f. `config/compliance/` vs `compliance/` — confusingly similar directory names

`config/compliance/` holds runtime baseline JSON files. `compliance/` holds OSCAL, Lula, and audit artefacts. The similar names cause confusion about which directory to look in for any given file.

**Action:** Rename `config/compliance/` → `config/baselines/` to make the distinction clear. Update all references in source code and CI.

### 10g. `docs/banking_regs.md` — lowercase filename inconsistent with all other docs

Every other file in `docs/` uses `UPPER_SNAKE_CASE.md`. This file uses `lower_snake_case.md`.

**Action:** Rename to `docs/compliance/BANKING_REGULATIONS.md`.

---

## 11. Files to Archive or Delete

### 11a. Definite deletes — generated, stale, or exact duplicates

| File | Reason |
|---|---|
| `audit_results.json` (root) | Superseded by v2 and v3; move to `compliance/audits/` as `audit_results_v1.json` |
| `integration_test_results.log` (root) | Generated log; add to `.gitignore` |
| `scratch/docs_summary.txt` | Generated text dump; no value in VCS |
| `deployment/__init__.py` | `deployment/` is not a Python package |
| `deployment/k8s_rendered/` (entire dir) | Duplicate templates — see §3d |
| `deployment/k8s/generated/` (entire dir) | Generated artefacts; gitignore instead |
| `deployment/k8s/current_deployment.yaml` | Stale cluster snapshot — see §3e |
| `deployment/k8s/live_deployment.yaml` | Stale cluster snapshot — see §3e |
| `deployment/docker/cloudbuild_gateway.yaml` | Duplicate of `cloudbuild.gateway.yaml` — see §3a |
| `proof/compliance-trigger-evidence.yaml` | Duplicate of root-level file — see §3f |
| `examples/evidence/.gitkeep` | Empty placeholder; gitignore the dir instead |
| `src/agentsight-ui/public/vite.svg` | Default Vite scaffold asset; replace with CAGE branding |
| `src/agentsight-ui/src/assets/react.svg` | Default Vite scaffold asset; unused in production |
| `infra/targets/gcp-gke/tfplan` | Terraform plan binary; add to `.gitignore` |
| `Dockerfile.vllm` (root) | Duplicate of `deployment/docker/Dockerfile.vllm` |

### 11b. Candidates for archival — move to `compliance/audits/`

| File | Recommended destination |
|---|---|
| `audit_results_v2.json` (root) | `compliance/audits/audit_results_v2.json` |
| `audit_results_v3.json` (root) | `compliance/audits/audit_results_v3.json` |
| `compliance-trigger-evidence.yaml` (root) | `compliance/audits/compliance-trigger-evidence.yaml` |
| `scratch/latency_baseline_v2.0.x.json` | `compliance/audits/perf/latency_baseline_v2.0.x.json` |
| `scratch/latency_post_opt_v2.0.x.json` | `compliance/audits/perf/latency_post_opt_v2.0.x.json` |

### 11c. Plans to convert to GitHub Issues then delete

| File | Action |
|---|---|
| `plans/release-readiness-gap-analysis.md` | Convert to closed GitHub issue |
| `plans/pre-release-doc-audit-remediation.md` | Convert to closed GitHub issue |
| `plans/path-b-deployment-plan.md` | Convert to closed GitHub issue |
| `plans/token-quota-proxy-impl-plan.md` | Convert to closed GitHub issue |
| `plans/poam-framework-redesign.md` | Move to `docs/poam/` if still active; otherwise close as issue |
| `plans/technical-report.md` | Merge into `docs/technical-report/` or delete if superseded |

### 11d. `.gitignore` additions required

The following patterns should be added to [`.gitignore`](../.gitignore):

```gitignore
# Generated Kubernetes manifests
deployment/k8s/generated/

# Terraform plan files
infra/targets/**/tfplan
*.tfplan

# Integration test logs
integration_test_results.log
*.log

# Scratch directory (use locally, never commit)
scratch/

# Evidence directories (populated at runtime)
examples/evidence/

# Compiled proto outputs (regenerate at build time)
src/agentsight-ui/src/protos/
```

---

## 12. Proposed Target Directory Hierarchy

The following is the recommended clean-state structure for the entire repository root. Only top-level directories and key files are shown; internal structure is described in the relevant sections above.

```
cybernetic-governance-engine/
│
├── README.md                        # Project overview (keep at root)
├── CHANGELOG.md                     # Keep at root (standard convention)
├── CONTRIBUTING.md                  # Keep at root (standard convention)
├── LICENSE
├── NOTICE
├── THIRD_PARTY_NOTICES.md
├── pyproject.toml
├── uv.lock
├── Makefile
├── deploy_all.sh
├── docker-compose.yaml              # Renamed from .yml
├── docker-compose.dev.yaml          # Renamed from .yml
├── pytest.ini
├── .gitignore
├── .dockerignore
├── .env.example
├── .env.development.example
├── .env.production.example
├── .gitmessage
├── .trivyignore
│
├── .github/                         # GitHub Actions & PR templates (unchanged)
│
├── assets/                          # Static assets
│   ├── cage-logo.png
│   └── financial-advisor.png        # Moved from docs/
│
├── compliance/                      # All compliance artefacts
│   ├── audits/                      # NEW — audit results & evidence
│   │   ├── audit_results_v1.json    # Renamed from audit_results.json
│   │   ├── audit_results_v2.json    # Moved from root
│   │   ├── audit_results_v3.json    # Moved from root
│   │   ├── compliance-trigger-evidence.yaml  # Moved from root & proof/
│   │   └── perf/
│   │       ├── latency_baseline_v2.0.x.json
│   │       └── latency_post_opt_v2.0.x.json
│   ├── boundary/
│   ├── categorization/
│   ├── continuous-monitoring/
│   ├── generated-policies/          # Populated by CI (currently empty)
│   ├── lula/
│   ├── oscal/
│   ├── pia/
│   ├── rar/
│   ├── risk_acceptance/
│   ├── sar/
│   ├── sbom/
│   └── ssp/
│
├── config/                          # Runtime configuration
│   ├── agent_scope.yaml
│   ├── control_mappings.json
│   ├── governance_thresholds.json
│   ├── safety_params.json           # Moved from src/gateway/governance/
│   ├── settings.py
│   ├── stpa_control_structure.yaml
│   ├── baselines/                   # Renamed from config/compliance/
│   │   ├── APAC_MAS_BASELINE.json
│   │   ├── EU_ECB_BASELINE.json
│   │   ├── US_FED_BASELINE.json
│   │   └── README.md
│   ├── opa/                         # NEW — all OPA policies
│   │   ├── generated_stpa_policy.rego
│   │   ├── system_authz.rego        # Moved from deployment/
│   │   └── trade_policy.rego        # Moved from src/.../graph/governance/
│   ├── oscal/
│   ├── rails/
│   └── thresholds/
│
├── deployment/                      # Deployment manifests & tooling
│   ├── README.md
│   ├── TERRAFORM_MIGRATION.md
│   ├── agentsight/
│   ├── dashboard/
│   ├── docker/                      # All Cloud Build configs & Dockerfiles
│   │   ├── cloudbuild.advisor.yaml
│   │   ├── cloudbuild.compliance.yaml  # Moved from root
│   │   ├── cloudbuild.gateway.yaml     # cloudbuild_gateway.yaml deleted
│   │   ├── cloudbuild.lula.yaml
│   │   ├── cloudbuild.ui.yaml          # Moved from root
│   │   ├── cloudbuild.vllm.yaml
│   │   ├── Dockerfile.lula
│   │   ├── Dockerfile.lula-runtime
│   │   ├── Dockerfile.nemo             # Moved from root
│   │   ├── Dockerfile.slm              # Moved from root
│   │   ├── Dockerfile.vllm
│   │   └── download_config.py
│   ├── k8s/
│   │   ├── base/                    # Static manifests (no templating)
│   │   ├── templates/               # .yaml.tpl files only
│   │   ├── inference-gateway/
│   │   └── docs/
│   │       ├── K8S_SECURITY_HARDENING.md
│   │       └── NAMESPACE-GUIDE.md
│   ├── langfuse/
│   └── scripts/                     # Deployment-specific scripts
│       ├── lib/                     # Moved from deployment/lib/
│       └── *.py / *.sh
│
├── docs/                            # All documentation
│   ├── README.md                    # Navigation index
│   ├── GOVERNANCE_OVERVIEW.md       # Renamed from README_GOVERNANCE.md
│   ├── architecture/
│   ├── compliance/
│   ├── nist-rmf/
│   ├── operations/
│   ├── poam/
│   ├── project/
│   ├── release/
│   ├── security/
│   └── technical-report/
│
├── examples/                        # Runnable demos (unchanged structure)
│   ├── README.md
│   ├── chaos_agent_playground.py
│   ├── governance_demo.py
│   └── telemetry.py
│
├── infra/                           # Terraform IaC (unchanged structure)
│   ├── modules/
│   └── targets/
│
├── mcp-servers/                     # MCP server implementations (unchanged)
│
├── scripts/                         # All operational & dev scripts
│   ├── automated_auditor.py
│   ├── build_images.sh
│   ├── canary_opa_policy.sh
│   ├── check_stpa_freshness.py
│   ├── deontic_policy_extractor.py
│   ├── evaluate_langfuse_traces.py
│   ├── fetch_langfuse_metrics.py    # Moved from root
│   ├── fix_mcp_configs.py
│   ├── generate_notices.sh
│   ├── generate_reasoning_manifest.py  # Moved from root
│   ├── generate_sbom.py
│   ├── get_env.py                   # Moved from root
│   ├── init_antigravity.sh          # Moved from root
│   ├── inspect_langfuse.py          # Moved from scratch/
│   ├── manage_langfuse_prompts.py
│   ├── migrate_prompts_to_langfuse.py
│   ├── patch_license.py
│   ├── port_forward_dev.sh          # Merged with start_port_forwards.sh
│   ├── proxy_backend.sh
│   ├── proxy_ui.sh
│   ├── replay_failed_scores.py
│   ├── run_agent_benchmark.py
│   ├── run_gke_load_test.sh
│   ├── run_langfuse_eval_test.sh
│   ├── setup_dev.sh                 # Moved from root
│   ├── setup_git_hooks.sh
│   ├── setup_test_env.sh            # Moved from root
│   ├── standardize_headers.py
│   ├── sync_langfuse_prompts.py
│   ├── update_secret.sh             # Moved from root
│   ├── verify_all.py                # Moved from root
│   ├── verify_colang_locally.py
│   ├── verify_langfuse_posture.py
│   ├── verify_proto_sync.py
│   ├── verify_remote.py
│   └── lib/                         # Moved from deployment/lib/
│       ├── __init__.py
│       ├── config.py
│       ├── gcp.py
│       └── utils.py
│
├── src/                             # All application source code
│   ├── agentsight-ui/               # Node.js frontend (documented as separate)
│   ├── compliance_bridge/
│   ├── gateway/
│   │   ├── governance/              # generated_* files gitignored or renamed
│   │   ├── server/
│   │   │   └── slm/                 # Moved from src/gateway/slm/
│   │   └── protos/                  # Single canonical proto source
│   ├── governed_financial_advisor/
│   │   └── agents/
│   │       └── explainer/
│   │           └── __init__.py      # Added (was missing)
│   └── cybernetic_governance_engine/  # Populate or remove
│
└── tests/                           # All tests
    ├── conftest.py
    ├── README.md
    ├── unit/
    ├── integration/
    ├── governance/
    ├── evaluation/
    ├── load/
    ├── red_team/                    # Merged with red_teaming/
    └── opa_snapshots/
```

---

## 13. Prioritised Action List

Actions are ordered by impact and risk. High-priority items fix correctness or security issues. Lower-priority items improve ergonomics.

### Priority 1 — Security & Correctness (do immediately)

| # | Action | Risk if deferred |
|---|---|---|
| 1.1 | Remove hardcoded `_GCP_PROJECT_ID: "YOUR_GCP_PROJECT_ID"` from `deployment/docker/cloudbuild.gateway.yaml` | Credential/project ID leak in public repo |
| 1.2 | Add `infra/targets/gcp-gke/tfplan` to `.gitignore` and delete the committed binary | Terraform state exposure |
| 1.3 | Add `integration_test_results.log` to `.gitignore` and delete from repo | Log data in VCS |
| 1.4 | Add `deployment/k8s/generated/` to `.gitignore` | Generated files drift from source |
| 1.5 | Add `scratch/` to `.gitignore` | Ephemeral work accidentally committed |
| 1.6 | Add `src/agentsight-ui/src/protos/` to `.gitignore` | Compiled outputs drift from proto source |
| 1.7 | Add missing `src/governed_financial_advisor/agents/explainer/__init__.py` | Import errors at runtime |

### Priority 2 — Duplicate Elimination (high value, low risk)

| # | Action |
|---|---|
| 2.1 | Delete `deployment/docker/cloudbuild_gateway.yaml` (duplicate of `cloudbuild.gateway.yaml`) |
| 2.2 | Delete `deployment/rebuild_backend.py` (duplicate of `deployment/scripts/rebuild_backend.py`) |
| 2.3 | Delete `deployment/k8s_rendered/` entirely (duplicate templates) |
| 2.4 | Delete `deployment/k8s/current_deployment.yaml` and `live_deployment.yaml` (stale snapshots) |
| 2.5 | Delete `proof/compliance-trigger-evidence.yaml` (duplicate of root-level file) |
| 2.6 | Delete root `Dockerfile.vllm` (duplicate of `deployment/docker/Dockerfile.vllm`) |
| 2.7 | Merge `start_port_forwards.sh` into `scripts/port_forward_dev.sh`, delete root copy |
| 2.8 | Remove `src/agentsight-ui/gateway_protos/` and replace with a build step from `src/gateway/protos/` |

### Priority 3 — Root-Level Cleanup (improves first impressions)

| # | Action |
|---|---|
| 3.1 | Move all 9 ad-hoc scripts from root → `scripts/` (see §2a) |
| 3.2 | Move `audit_results*.json` from root → `compliance/audits/` (see §2b) |
| 3.3 | Move `cloudbuild.compliance.yaml` and `cloudbuild.ui.yaml` from root → `deployment/docker/` |
| 3.4 | Move `compliance-trigger-evidence.yaml` from root → `compliance/audits/` |
| 3.5 | Move `ARCHITECTURE.md` from root → `docs/architecture/` |
| 3.6 | Rename and move `README_GOVERNANCE.md` → `docs/GOVERNANCE_OVERVIEW.md` |
| 3.7 | Delete `deployment/__init__.py` |

### Priority 4 — Directory Restructuring (medium effort, high long-term value)

| # | Action |
|---|---|
| 4.1 | Reorganise `docs/` into sub-directories per §7b |
| 4.2 | Reorganise `tests/` into sub-directories per §6c |
| 4.3 | Move `deployment/lib/` → `scripts/lib/` and update imports |
| 4.4 | Move `deployment/system_authz.rego` → `config/opa/system_authz.rego` |
| 4.5 | Move `src/governed_financial_advisor/graph/governance/trade_policy.rego` → `config/opa/trade_policy.rego` |
| 4.6 | Move `config/compliance/reconciliation_worker.py` → `src/compliance_bridge/reconciliation_worker.py` |
| 4.7 | Rename `config/compliance/` → `config/baselines/` and update all references |
| 4.8 | Rename `docs/banking_regs.md` → `docs/compliance/BANKING_REGULATIONS.md` |
| 4.9 | Rename `docs/POAM.md` → `docs/poam/POAM_MASTER.md` |

### Priority 5 — Source Code Tidying (lower risk, improves maintainability)

| # | Action |
|---|---|
| 5.1 | Move `src/gateway/slm/` → `src/gateway/server/slm/` |
| 5.2 | Move `src/gateway/governance/safety_params.json` → `config/safety_params.json` |
| 5.3 | Resolve `generated_` prefix on `generated_saga_nodes.py` and `generated_stpa_validator.py` |
| 5.4 | Populate or remove `src/cybernetic_governance_engine/` |
| 5.5 | Move root Dockerfiles (`Dockerfile.nemo`, `Dockerfile.slm`) → `deployment/docker/` |
| 5.6 | Rename `docker-compose.yml` → `docker-compose.yaml` and `docker-compose.dev.yml` → `docker-compose.dev.yaml` |

### Priority 6 — Archive & Delete Ephemeral Content (housekeeping)

| # | Action |
|---|---|
| 6.1 | Triage `scratch/` — relocate useful files, delete the rest, then remove the directory |
| 6.2 | Convert `plans/` documents to GitHub Issues, then delete the directory |
| 6.3 | Delete `proof/` after relocating its two files |
| 6.4 | Rename sprint-named test files: `test_sprint2_high_severity.py` → `test_security_high_severity.py` |
| 6.5 | Merge `tests/red_teaming/` into `tests/red_team/` |
| 6.6 | Remove `examples/evidence/.gitkeep`; add `examples/evidence/` to `.gitignore` |
| 6.7 | Remove default Vite scaffold assets (`vite.svg`, `react.svg`) from `src/agentsight-ui/` |
| 6.8 | Remove `compliance/generated-policies/` placeholder or populate it |

---

*End of Repository Cleanup Plan*
