# Cross OSS Compliance Remediation Plan — CAGE

**Prepared:** 2026-07-07
**Analyst:** Roo (Architect mode)
**Companion to:** `plans/OSS_READINESS_PLAN.md`
**Branch:** `chore/cross-oss-remediation`
**Change Classification:** Cat-S (Standard) — pre-approved OSS readiness pattern; no new GCP services, no new external APIs, no NIST HIGH-impact control changes.

---

## Executive Summary

The Google Cross OSS compliance tool scanned the `cybernetic-governance-engine` repository and produced:

| Severity | Count | Category |
|---|---|---|
| **Required (blocking)** | 51 | Missing Apache 2.0 license headers |
| **Potential (warning)** | 33 | Leaking terms / inclusive language / large file count |
| **Total** | **84** | |

Breakdown of the 33 potential issues:

| Sub-category | Files | Action |
|---|---|---|
| `trade-secret` | 2 | False positive — document |
| `backdoor` | 9 | False positive — document + inline comment |
| `blacklist` | 5 | **Must fix** — rename to `denylist`/`blocklist` |
| `whitelist` | 3 | **Must fix** — rename to `allowlist` |
| `confidential` | 6 | Mixed — 5 false positives, 1 real fix |
| `internal only` | 4 | Mixed — 3 rephrase, 1 OPA variable rename |
| `sandbox.` | 1 | False positive — document |
| Large file count (792) | — | OSPO human review required |

This plan is organized into four implementation phases plus an automation script design and verification steps. All work executes on branch `chore/cross-oss-remediation` branched from `main`.

---

## Phase 1: License Headers (Required — Blocking)

**Priority: P0 — must complete before any public push.**

### 1.1 Discovery — Finding the 7 Truncated Files

Cross reported 51 required fixes but truncated the list at 44 confirmed files. Run the following commands to discover all remaining files missing headers:

```bash
# Python files missing the Apache header
grep -rL "Apache License" \
  --include="*.py" \
  . \
  | grep -v ".venv" | grep -v "__pycache__" | grep -v ".git"

# YAML/YML files missing the Apache header
grep -rL "Apache License" \
  --include="*.yaml" \
  --include="*.yml" \
  . \
  | grep -v ".venv" | grep -v ".git"
```

The 7 truncated files are expected to be additional `__init__.py` files in `mcp-servers/` or `scripts/` subdirectories. The grep output is authoritative — treat it as the definitive file list.

### 1.2 Required Header Text

**For Python files (`.py`):**

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

**For YAML files (`.yaml`, `.yml`):**

```yaml
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

> **YAML document separator note:** Several YAML files begin with `---` (the YAML document separator). The license header must be prepended **before** the `---` separator, not after it. The `---` separator remains on the line immediately following the header block.

### 1.3 Confirmed Files Requiring Headers

#### GitHub Workflows (3 files)

| File | Notes |
|---|---|
| `.github/workflows/compliance-matrix.yml` | YAML header |
| `.github/workflows/dependency-review.yml` | YAML header |
| `.github/workflows/sbom.yml` | YAML header |

#### Compliance / Lula (23 files)

| File | Notes |
|---|---|
| `compliance/lula/assessment-results.yaml` | YAML header |
| `compliance/lula/drafts/lula-validation-iso001-token-quota.yaml` | YAML header |
| `compliance/lula/lula-validation-a52.yaml` | YAML header |
| `compliance/lula/lula-validation-a53.yaml` | YAML header |
| `compliance/lula/lula-validation-a92.yaml` | YAML header |
| `compliance/lula/lula-validation-aarm-vectors.yaml` | YAML header |
| `compliance/lula/lula-validation-ac2.yaml` | YAML header |
| `compliance/lula/lula-validation-ac3.yaml` | YAML header |
| `compliance/lula/lula-validation-au12.yaml` | YAML header |
| `compliance/lula/lula-validation-cm6.yaml` | YAML header |
| `compliance/lula/lula-validation-dora-art10.yaml` | YAML header |
| `compliance/lula/lula-validation-eu-ai-act-art9.yaml` | YAML header |
| `compliance/lula/lula-validation-gdpr-art22.yaml` | YAML header |
| `compliance/lula/lula-validation-ia3.yaml` | YAML header |
| `compliance/lula/lula-validation-ia5.yaml` | YAML header |
| `compliance/lula/lula-validation-ir6.yaml` | YAML header |
| `compliance/lula/lula-validation-mas-feat.yaml` | YAML header |
| `compliance/lula/lula-validation-mas-notice655.yaml` | YAML header |
| `compliance/lula/lula-validation-mas-trm-s6.yaml` | YAML header |
| `compliance/lula/lula-validation-ra5.yaml` | YAML header |
| `compliance/lula/lula-validation-sc4.yaml` | YAML header |
| `compliance/lula/lula-validation-sc8.yaml` | YAML header |
| `compliance/lula/lula-validation-si2.yaml` | YAML header |

#### Compliance / OSCAL (11 files)

| File | Notes |
|---|---|
| `compliance/oscal/common-controls-catalog.yaml` | YAML header |
| `compliance/oscal/component-definition.yaml` | YAML header |
| `compliance/oscal/eu-ai-act-profile.yaml` | YAML header |
| `compliance/oscal/information-type-registry.yaml` | YAML header |
| `compliance/oscal/mas-feat-profile.yaml` | YAML header |
| `compliance/oscal/sp800-53-component-definition.yaml` | YAML header |
| `compliance/oscal/sp800053-profile.yaml` | YAML header |
| `compliance/oscal/stpa_compiler_ssp_patch.yaml` | YAML header |
| `compliance/oscal/system-security-plan-apac-mas.yaml` | YAML header |
| `compliance/oscal/system-security-plan-eu-ecb.yaml` | YAML header |
| `compliance/oscal/system-security-plan.yaml` | YAML header |

#### Config (3 files)

| File | Notes |
|---|---|
| `config/agent_scope.yaml` | YAML header |
| `config/stpa_control_structure.yaml` | YAML header |
| `config/thresholds/token_quota.yaml` | YAML header |

#### Deployment / Docker (3 files)

| File | Notes |
|---|---|
| `deployment/docker/cloudbuild.compliance.yaml` | YAML header |
| `deployment/docker/cloudbuild.lula.yaml` | YAML header |
| `deployment/docker/cloudbuild.ui.yaml` | YAML header |

#### Deployment / Kubernetes (5 files)

| File | Notes |
|---|---|
| `deployment/k8s/gateway-hpa.yaml` | YAML header |
| `deployment/k8s/gateway.yaml` | YAML header |
| `deployment/k8s/gcp/ingress-gke.yaml` | YAML header |
| `deployment/k8s/ingress.yaml` | YAML header |
| `deployment/k8s/vllm-namespace.yaml` | YAML header |

#### Python `__init__.py` files (2 confirmed + 7 to discover via grep)

| File | Notes |
|---|---|
| `mcp-servers/infrastructure/mcp_servers/__init__.py` | Python header |
| `mcp-servers/infrastructure/mcp_servers/infrastructure/__init__.py` | Python header |
| *(7 additional — run grep from §1.1 to identify)* | Python header |

### 1.4 Automation Script Design — `scripts/add_license_headers.sh`

The recommended approach is a single idempotent shell script. Design specification:

```bash
#!/usr/bin/env bash
# scripts/add_license_headers.sh
#
# Prepends Apache 2.0 license headers to all files missing them.
# Idempotent: skips files that already contain "Apache License".
# Usage:
#   ./scripts/add_license_headers.sh          # apply headers
#   ./scripts/add_license_headers.sh --check  # exit 1 if any file is missing a header (CI mode)

set -euo pipefail

PY_HEADER=$(cat <<'EOF'
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

EOF
)

YAML_HEADER=$(cat <<'EOF'
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

EOF
)

CHECK_MODE=false
[[ "${1:-}" == "--check" ]] && CHECK_MODE=true

MISSING=()

prepend_header() {
  local file="$1"
  local header="$2"
  if grep -q "Apache License" "$file"; then
    return 0  # already has header — skip
  fi
  if $CHECK_MODE; then
    MISSING+=("$file")
    return 0
  fi
  # Prepend header using a temp file (handles files starting with ---)
  local tmp
  tmp=$(mktemp)
  printf '%s' "$header" > "$tmp"
  cat "$file" >> "$tmp"
  mv "$tmp" "$file"
  echo "  [added] $file"
}

# Python files
while IFS= read -r -d '' f; do
  prepend_header "$f" "$PY_HEADER"
done < <(grep -rLZ "Apache License" --include="*.py" \
  --exclude-dir=".venv" --exclude-dir="__pycache__" --exclude-dir=".git" .)

# YAML/YML files
while IFS= read -r -d '' f; do
  prepend_header "$f" "$YAML_HEADER"
done < <(grep -rLZ "Apache License" --include="*.yaml" --include="*.yml" \
  --exclude-dir=".venv" --exclude-dir=".git" .)

if $CHECK_MODE; then
  if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "ERROR: ${#MISSING[@]} file(s) missing Apache 2.0 license header:"
    printf '  %s\n' "${MISSING[@]}"
    exit 1
  else
    echo "OK: All files have Apache 2.0 license headers."
  fi
fi
```

**Key properties:**
- Idempotent: checks for `"Apache License"` string before prepending — will never double-add.
- `--check` mode: exits with code 1 if any file is missing a header; suitable for CI enforcement.
- Handles YAML files that begin with `---` correctly (prepends before the separator).
- Excludes `.venv`, `__pycache__`, `.git` directories.

**Commit for this phase:**
```
chore(ci): add license headers to all yaml and mcp-server py files

Adds Apache 2.0 headers to 51 files flagged by the Cross OSS tool:
- 23 compliance/lula/*.yaml
- 11 compliance/oscal/*.yaml
- 5 deployment/k8s/*.yaml
- 3 deployment/docker/cloudbuild.*.yaml
- 3 .github/workflows/*.yml
- 3 config/*.yaml
- 2+ mcp-servers/**/__init__.py (+ 7 discovered via grep)

Adds scripts/add_license_headers.sh for idempotent CI enforcement.
```

---

## Phase 2: Inclusive Language Remediation (Required — Blocking)

**Priority: P1 — required before OSS release; blocking per Cross tool.**

All `blacklist`/`whitelist` occurrences must be renamed. Changes are cascading: the config key rename in `config/stpa_control_structure.yaml` must propagate to `src/gateway/governance/stpa_compiler.py`.

### 2.1 `config/stpa_control_structure.yaml` — `currency_blacklist` → `currency_denylist`

**File:** `config/stpa_control_structure.yaml`
**Lines:** 336, 345

```yaml
# BEFORE (lines 336 and 345):
        - currency_blacklist: [BTC]

# AFTER:
        - currency_denylist: [BTC]
```

> ⚠️ **Breaking change risk:** This is a YAML config key rename. Any consumer that reads `currency_blacklist` directly will break. The only known consumer is `src/gateway/governance/stpa_compiler.py` (see §2.2 below). Verify with:
> ```bash
> grep -r "currency_blacklist" --include="*.py" --include="*.yaml" --include="*.yml" .
> ```
> If additional consumers are found, update them in the same commit.

### 2.2 `src/gateway/governance/stpa_compiler.py` — `blacklist` variable + config key reference

**File:** `src/gateway/governance/stpa_compiler.py`
**Lines:** 420–448

```python
# BEFORE:
blacklist = []
if role.restrictions:
    for r in role.restrictions:
        blacklist.extend(r.get("currency_blacklist", []))

blacklist_str = (
    " ".join(f'"{c}"' not in [""] and f'input.currency != "{c}"' for c in blacklist)
    if blacklist
    else ""
)
# ... and later:
for c in blacklist:
    lines.append(f'    input.currency != "{c}"')

# AFTER:
denylist = []
if role.restrictions:
    for r in role.restrictions:
        denylist.extend(r.get("currency_denylist", []))

denylist_str = (
    " ".join(f'"{c}"' not in [""] and f'input.currency != "{c}"' for c in denylist)
    if denylist
    else ""
)
# ... and later:
for c in denylist:
    lines.append(f'    input.currency != "{c}"')
```

All occurrences of `blacklist` and `blacklist_str` in this function must be renamed to `denylist` and `denylist_str` respectively. The config key lookup `r.get("currency_blacklist", [])` must change to `r.get("currency_denylist", [])` to match the config change in §2.1.

### 2.3 `deployment/k8s/nemo-rails-configmap.yaml` — `WHITELIST`/`BLACKLIST` in inline Python

**File:** `deployment/k8s/nemo-rails-configmap.yaml`
**Lines:** 97, 106, 127, 138, 245

This file embeds inline Python code and comments as a ConfigMap value. The following substitutions are required:

| Before | After | Context |
|---|---|---|
| `# STAGE 1: WHITELIST - Fast-path for known-safe...` | `# STAGE 1: ALLOWLIST - Fast-path for known-safe...` | Comment in inline Python |
| `# STAGE 2: BLACKLIST - Fast-path for obvious jailbreak...` | `# STAGE 2: BLOCKLIST - Fast-path for obvious jailbreak...` | Comment in inline Python |
| `Harmful pattern blacklist → BLOCK` | `Harmful pattern blocklist → BLOCK` | Comment string |
| `# STAGE 2: BLACKLIST - Harmful patterns` | `# STAGE 2: BLOCKLIST - Harmful patterns` | Comment in inline Python |
| `financial domain whitelist + jailbreak blacklist` | `financial domain allowlist + jailbreak blocklist` | Comment in YAML |

> **Note:** These are comments and stage-label strings inside the ConfigMap's inline Python. They do not affect runtime behavior — only naming. No functional logic changes.

### 2.4 `config/rails/actions.py` — `WHITELIST`/`BLACKLIST` stage labels

**File:** `config/rails/actions.py`
**Lines:** 203, 204, 226, 237, 241, 252, 285, 319, 328

> **Note:** This file already has the correct Apache 2.0 license header (lines 1–13). No header change needed.

Search for all occurrences:
```bash
grep -n "WHITELIST\|BLACKLIST\|whitelist\|blacklist" config/rails/actions.py
```

Replace all stage-label comments and variable names:

| Before | After |
|---|---|
| `# STAGE 1: WHITELIST` | `# STAGE 1: ALLOWLIST` |
| `# STAGE 2: BLACKLIST` | `# STAGE 2: BLOCKLIST` |
| Any variable named `whitelist_*` | `allowlist_*` |
| Any variable named `blacklist_*` | `blocklist_*` |

Verify no functional logic is broken — these are comment labels and local variable names only.

### 2.5 `src/governed_financial_advisor/infrastructure/telemetry/nemo_exporter.py` — `whitelist` comment/variable

**File:** `src/governed_financial_advisor/infrastructure/telemetry/nemo_exporter.py`
**Lines:** 47, 93

```python
# BEFORE (line 47):
# Explicit whitelist of action names that must always be traced, even when they
# do not match the "check" / "guard" / "detect" keyword heuristic.

# AFTER (line 47):
# Explicit allowlist of action names that must always be traced, even when they
# do not match the "check" / "guard" / "detect" keyword heuristic.
```

```python
# BEFORE (line 93):
# and on any explicitly whitelisted safety action names.

# AFTER (line 93):
# and on any explicitly allowlisted safety action names.
```

> These are comment-only changes. The variable `_TRACED_ACTION_NAMES` itself is already well-named and does not need renaming.

**Commit for Phase 2:**
```
chore(governance): rename blacklist/whitelist to denylist/allowlist

Renames non-inclusive language flagged by Cross OSS tool:
- config/stpa_control_structure.yaml: currency_blacklist → currency_denylist
- src/gateway/governance/stpa_compiler.py: blacklist var + config key lookup
- deployment/k8s/nemo-rails-configmap.yaml: stage label comments
- config/rails/actions.py: stage label comments and variable names
- src/.../nemo_exporter.py: comment-only rename

Cascading change: stpa_compiler.py updated in same commit as config key
rename to keep the system consistent.
```

---

## Phase 3: False Positive Documentation and Minor Real Fixes

**Priority: P2 — required before OSS release but not blocking CI.**

### 3.1 Create `CROSS_FALSE_POSITIVES.md`

Create a new file at the repository root: `CROSS_FALSE_POSITIVES.md`

This file serves as the OSPO-facing justification document for all Cross tool warnings that are confirmed false positives. Structure:

```markdown
# Cross OSS Tool — False Positive Registry

**Scan date:** 2026-07-07
**Tool:** Google Cross OSS compliance scanner
**Maintainer:** CAGE project OSPO contact

This document records all Cross tool warnings that have been reviewed and
confirmed as false positives. Each entry includes the file, line(s), the
flagged term, and the justification for why it is not a compliance concern.

---

## `trade-secret` — 2 occurrences (FALSE POSITIVE)

| File | Lines | Justification |
|---|---|---|
| `docs/NIST_AI_600_1_US_FED_ANALYSIS.md` | 489, 491 | Quoting the official NIST AI 600-1 definition of IP risk. This is security analysis content reproducing a regulatory document's terminology, not a leaked internal trade secret. |
| `docs/compliance/us_fed/NIST_AI_600_1_US_FED_ANALYSIS.md` | 489, 491 | Same as above — this is a regional copy of the same analysis document. |

## `backdoor` — 14 occurrences across 9 files (ALL FALSE POSITIVE)

All occurrences fall into two categories:

**Category A — Causal ML library terminology (DoWhy/CausalPy API):**
The term "backdoor" is a standard causal inference term (Pearl's backdoor criterion)
used throughout the DoWhy and CausalPy libraries. The string
`method_name="backdoor.linear_regression"` in
`src/gateway/governance/causal_gatekeeper.py` line 583 is a verbatim DoWhy
API parameter — it cannot be renamed as it is a third-party library interface.

**Category B — Security threat descriptions in documentation:**
References in POAM, risk assessment reports, and NIST analysis documents
describe "backdoor attacks" as a threat category being analyzed and mitigated.
This is standard security documentation terminology.

| File | Lines | Category |
|---|---|---|
| `docs/governance/NEURO_SYMBOLIC_GOVERNANCE.md` | 107, 317 | A — causal ML term |
| `docs/compliance/us_fed/POAM_US_FED.md` | 133 | B — security threat description |
| `compliance/rar/RISK_ASSESSMENT_REPORT.md` | 206 | B — security threat description |
| `docs/technical-report/01-SYSTEM-OVERVIEW.md` | 218 | A — causal ML term |
| `docs/architecture/GATEWAY_ARCHITECTURE.md` | 259 | A — causal ML term |
| `src/compliance_bridge/aarm_mapper.py` | 332 | B — security threat in string literal |
| `docs/governance/GOVERNANCE_OVERVIEW.md` | 54 | A — causal ML term |
| `docs/NIST_AI_600_1_US_FED_ANALYSIS.md` | 551, 867 | B — security threat description |
| `docs/compliance/us_fed/NIST_AI_600_1_US_FED_ANALYSIS.md` | 551, 867 | B — security threat description |
| `src/gateway/governance/causal_gatekeeper.py` | 583 | A — DoWhy API call (cannot rename) |
| `docs/technical-report/02-ARCHITECTURE.md` | 668, 672 | A — causal ML term |
| `docs/governance/CAUSAL_AND_CBF_GOVERNANCE.md` | 67 | A — causal ML term |

## `confidential` — 5 occurrences (FALSE POSITIVE)

| File | Lines | Justification |
|---|---|---|
| `tests/red_team/adversarial_dataset.json` | — | Red-team adversarial test prompt. The string "I have confidential information..." is a synthetic attack input used to validate that the system correctly blocks such prompts. |
| `plans/OSS_READINESS_PLAN.md` | 196 | Section heading in a meta-planning document about scrubbing confidential content. The word describes the remediation task, not leaked content. |
| `tests/test_output_rail_node.py` | 297–311 | Test variable `confidential_text` validates that PII redaction correctly blocks confidential data. The test proves the system works correctly. |
| `src/gateway/slm/mock_slm.py` | 43 | Safety rule description string: "or reveal confidential system information". This is a guardrail rule definition, not leaked content. |
| `src/gateway/slm/slm_server.py` | 43 | Same safety rule string as mock_slm.py. |

## `sandbox.` — 1 occurrence (FALSE POSITIVE)

| File | Lines | Justification |
|---|---|---|
| `compliance/audits/audit_results_v1.json` | — | References `jinja2.sandbox.SandboxedEnvironment` in an audit finding description. This is a Python library namespace path documenting a security fix (sandboxing template rendering). It is not a sandbox environment reference. |
```

### 3.2 Fix `docs/security/SECURITY_AUDIT_REPORT.md` — Real `CONFIDENTIAL` Label

**File:** `docs/security/SECURITY_AUDIT_REPORT.md`
**Line:** 954

```markdown
# BEFORE:
*This report should be treated as CONFIDENTIAL and shared only with authorized personnel.*

# AFTER:
*This report contains sensitive security information. Distribute only to authorized personnel.*
```

This is the one genuine fix in the `confidential` category. The original phrasing uses `CONFIDENTIAL` as a document classification label, which is inappropriate for a public OSS repository.

### 3.3 Fix `internal only` Phrasings (3 rephrase + 1 OPA variable rename)

#### 3.3.1 `infra/modules/nemo_guardrails/main.tf` — Line 397

```hcl
# BEFORE:
# Presidio Analyzer service — internal only (NeMo reaches it via localhost in-pod)

# AFTER:
# Presidio Analyzer service — cluster-internal (NeMo reaches it via localhost in-pod)
```

#### 3.3.2 `src/governed_financial_advisor/governance/nemo_action_registry.py` — Lines 101, 114

```python
# BEFORE (line 101):
#    2. Symbolic-governor async actions come next — gateway-internal only,

# AFTER (line 101):
#    2. Symbolic-governor async actions come next — gateway-scoped only,

# BEFORE (line 114):
# Gateway actions (src.gateway.governance.nemo.actions) are gateway-internal only, not registered here.

# AFTER (line 114):
# Gateway actions (src.gateway.governance.nemo.actions) are gateway-scoped only, not registered here.
```

#### 3.3.3 `deployment/langfuse/README.md` — Line 41

```markdown
# BEFORE:
- **Access**: Internal only via `http://minio.governance-stack.svc.cluster.local:9000`.

# AFTER:
- **Access**: Cluster-internal only via `http://minio.governance-stack.svc.cluster.local:9000`.
```

#### 3.3.4 `compliance/lula/lula-validation-sc8.yaml` — OPA variable `is_internal_only`

This file contains an OPA policy with a variable named `is_internal_only`. This is a code identifier embedded in a YAML string (the Lula validation spec). The rename requires:

1. In `compliance/lula/lula-validation-sc8.yaml`: rename `is_internal_only` → `is_cluster_internal` in the embedded OPA Rego policy string.
2. Search for any other files that reference this OPA variable by name:
   ```bash
   grep -r "is_internal_only" --include="*.yaml" --include="*.yml" --include="*.rego" .
   ```
3. Update all references found in the same commit.

> **Note:** This is a Lula validation file that also requires a license header (listed in Phase 1, §1.3). Apply both changes in the same commit to avoid two separate edits to the same file.

### 3.4 Add Inline Comment to `src/gateway/governance/causal_gatekeeper.py` — DoWhy API

**File:** `src/gateway/governance/causal_gatekeeper.py`
**Line:** 583

Add a comment immediately above the DoWhy API call to explain the `backdoor` term:

```python
# NOTE: "backdoor.linear_regression" is a DoWhy library API method name
# (Pearl's backdoor criterion for causal effect estimation). This is not
# a security backdoor — it is standard causal inference terminology.
# See: https://www.pywhy.org/dowhy/main/user_guide/effect_identification/id-algorithm.html
result = model.estimate_effect(
    identified_estimand,
    method_name="backdoor.linear_regression",
    ...
)
```

**Commit for Phase 3:**
```
docs(compliance): document Cross false positives and fix real warnings

- Add CROSS_FALSE_POSITIVES.md with OSPO justification for all 28
  confirmed false positives (trade-secret x2, backdoor x14,
  confidential x5, sandbox x1, internal-only x3 comments)
- Fix docs/security/SECURITY_AUDIT_REPORT.md line 954: remove
  CONFIDENTIAL classification label inappropriate for public OSS
- Rephrase "internal only" comments in 3 files to "cluster-internal"
  or "gateway-scoped"
- Rename OPA variable is_internal_only → is_cluster_internal in
  compliance/lula/lula-validation-sc8.yaml
- Add explanatory comment for DoWhy backdoor.linear_regression API call
```

---

## Phase 4: OSPO Human Review — Large File Count

**Priority: P3 — informational; no automated fix possible.**

### 4.1 Finding

Cross flagged the repository as having **792 files**, which exceeds the threshold that triggers mandatory OSPO human review. This is not an automated fix — it requires a human OSPO reviewer to confirm:

1. No files contain unreleased proprietary algorithms or trade secrets.
2. No files contain personal data (PII) of real individuals.
3. No files contain internal Google infrastructure details beyond what is already being remediated in `plans/OSS_READINESS_PLAN.md`.
4. The compliance evidence files (`compliance/audits/`, `compliance/lula/assessment-results.yaml`) are appropriate for public release.
5.