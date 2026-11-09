#!/usr/bin/env bash
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

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_DIR="$(git rev-parse --git-path hooks)"
mkdir -p "${HOOKS_DIR}"

# Preserve chained hook wrappers that delegate via:
#   orig="$(dirname "$0")/<hook>.<suffix>"
resolve_hook_target() {
  local hook_name="$1"
  local hook_path="${HOOKS_DIR}/${hook_name}"
  if [[ -f "${hook_path}" ]]; then
    local delegated
    delegated="$(sed -n 's#^orig="\$(dirname "\$0")/\('"${hook_name}"'\.[A-Za-z0-9_.-]*\)"$#\1#p' "${hook_path}" | head -n 1)"
    if [[ -n "${delegated}" ]]; then
      printf '%s/%s\n' "${HOOKS_DIR}" "${delegated}"
      return
    fi
  fi
  printf '%s\n' "${hook_path}"
}

echo "→ Installing commit message template..."
git config commit.template "${REPO_ROOT}/.gitmessage"

echo "→ Installing pre-commit hook (ruff, mypy, and deterministic CI gates)..."
PRECOMMIT_FILE="$(resolve_hook_target pre-commit)"
cat > "${PRECOMMIT_FILE}" << 'HOOK'
#!/usr/bin/env bash
# Deterministic pre-commit gate synchronized with .github/workflows/ci.yml
set -euo pipefail

top="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${top}" ]] || [[ ! -f "${top}/scripts/check_import_boundaries.py" ]]; then
  exit 0
fi

common_root="$(cd "$(git rev-parse --git-common-dir)/.." 2>/dev/null && pwd || true)"
venv_bin=""
if [[ -x "${top}/.venv/bin/python" ]]; then
  venv_bin="${top}/.venv/bin"
elif [[ -n "${common_root}" ]] && [[ -x "${common_root}/.venv/bin/python" ]]; then
  venv_bin="${common_root}/.venv/bin"
fi

resolve_tool() {
  local tool="$1"
  if [[ -n "${venv_bin}" ]] && [[ -x "${venv_bin}/${tool}" ]]; then
    printf '%s\n' "${venv_bin}/${tool}"
    return 0
  fi
  if command -v "${tool}" >/dev/null 2>&1; then
    command -v "${tool}"
    return 0
  fi
  echo "❌  pre-commit: required tool '${tool}' not found in .venv or PATH." >&2
  exit 1
}

repo_py="$(resolve_tool python)"
repo_ruff="$(resolve_tool ruff)"
repo_mypy="$(resolve_tool mypy)"

cd "${top}"

"${repo_ruff}" check .
"${repo_ruff}" format --check .
"${repo_mypy}" src/

for gate_script in \
  scripts/check_import_boundaries.py \
  scripts/check_posture_guard_integrity.py \
  scripts/check_model_free_install.py \
  scripts/check_conformance_sync.py \
  scripts/check_client_sdk_sync.py \
  scripts/check_domain_literals.py \
  scripts/check_telemetry_literals.py \
  scripts/check_vendor_brands.py \
  scripts/check_project_id_hygiene.py \
  scripts/check_doc_references.py \
  scripts/check_partner_headers.py \
  scripts/check_yaml_unique_keys.py \
  scripts/check_write_only_state.py \
  scripts/check_daemon_lifespans.py \
  scripts/check_lula_stub_count.py \
  scripts/check_poam_lula_divergence.py \
  scripts/check_producer_consumer_keys.py \
  scripts/check_k8s_terraform_parity.py \
  scripts/check_stpa_freshness.py \
  scripts/check_ai600_lula_manifests.py
do
  if [[ -f "${gate_script}" ]]; then
    "${repo_py}" "${gate_script}"
  fi
done

if [[ -f "scripts/check_oscal_claim_census.py" ]]; then
  "${repo_py}" scripts/check_oscal_claim_census.py \
    --verify-rendered docs/compliance/OSCAL_EVIDENCE_CLAIM_REGISTER.md
fi

if [[ -f "scripts/generate_agent_state_schema.py" ]]; then
  "${repo_py}" scripts/generate_agent_state_schema.py --check
fi

"${repo_py}" - <<'PY'
import ast
import pathlib
import re
import sys

# 1. Apache 2.0 license header check (matches .github/workflows/ci.yml license-check)
missing_headers: list[str] = []
src_root = pathlib.Path("src")
if src_root.is_dir():
    for ext in ("*.py", "*.js", "*.ts", "*.tsx"):
        for p in sorted(src_root.rglob(ext)):
            txt = p.read_text(encoding="utf-8", errors="replace")
            if "Apache License" not in txt and "Copyright 2026" not in txt:
                missing_headers.append(str(p))
if missing_headers:
    sys.stderr.write("pre-commit: missing Apache 2.0 license header in:\n")
    for m in missing_headers:
        sys.stderr.write(f"  {m}\n")
    sys.exit(1)

# 2. Pytest selection-marker contract check (matches tests/conftest.py SELECTION_MARKERS)
selection_markers = {
    "unit",
    "local",
    "integration",
    "load",
    "chaos",
    "live_external",
    "partner_integration",
    "e2e",
}


def markers_in_expr(node: ast.AST) -> set[str]:
    found: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Attribute):
            if getattr(sub.value, "attr", None) == "mark":
                found.add(sub.attr)
    return found


offenders: list[str] = []
tests_root = pathlib.Path("tests")
if tests_root.is_dir():
    for p in sorted(tests_root.rglob("test_*.py")):
        tree = ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
        mod_markers: set[str] = set()
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    if isinstance(t, ast.Name) and t.id == "pytestmark":
                        mod_markers |= markers_in_expr(stmt.value)
            elif (
                isinstance(stmt, ast.AnnAssign)
                and isinstance(stmt.target, ast.Name)
                and stmt.target.id == "pytestmark"
                and stmt.value is not None
            ):
                mod_markers |= markers_in_expr(stmt.value)
        if mod_markers & selection_markers:
            continue
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name.startswith("test_"):
                fn_m: set[str] = set()
                for d in stmt.decorator_list:
                    fn_m |= markers_in_expr(d)
                if not (fn_m & selection_markers):
                    offenders.append(f"{p}::{stmt.name}")
            elif isinstance(stmt, ast.ClassDef) and stmt.name.startswith("Test"):
                cls_m: set[str] = set()
                for d in stmt.decorator_list:
                    cls_m |= markers_in_expr(d)
                for b in stmt.body:
                    if isinstance(b, ast.Assign):
                        for t in b.targets:
                            if isinstance(t, ast.Name) and t.id == "pytestmark":
                                cls_m |= markers_in_expr(b.value)
                if cls_m & selection_markers:
                    continue
                for b in stmt.body:
                    if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef)) and b.name.startswith("test_"):
                        fn_m = set()
                        for d in b.decorator_list:
                            fn_m |= markers_in_expr(d)
                        if not (fn_m & selection_markers):
                            offenders.append(f"{p}::{stmt.name}::{b.name}")
if offenders:
    sys.stderr.write(
        f"pre-commit: pytest selection-marker contract violation ({len(offenders)} unmarked test(s)):\n"
    )
    for o in offenders[:15]:
        sys.stderr.write(f"  {o}\n")
    sys.exit(1)

# 3. NeMo actions.py ConfigMap snapshot freshness (matches ci.yml nemo-freshness-check)
configmap_path = pathlib.Path("infra/modules/nemo_guardrails/nemo-rails-configmap.yaml")
canonical_path = pathlib.Path("config/rails/actions.py")
if configmap_path.is_file() and canonical_path.is_file():
    snapshot_lines: list[str] = []
    in_block = False
    block_indent = 0
    for line in configmap_path.read_text(encoding="utf-8").splitlines(keepends=True):
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if not in_block:
            if stripped.startswith("actions.py:"):
                in_block = True
                block_indent = indent + 2
            continue
        if stripped == "" or indent >= block_indent:
            snapshot_lines.append(line[block_indent:] if stripped else "\n")
        else:
            break
    snapshot = "".join(snapshot_lines).rstrip("\n") + "\n"
    canonical = canonical_path.read_text(encoding="utf-8")
    if not snapshot_lines or snapshot != canonical:
        sys.stderr.write(
            "pre-commit: infra/modules/nemo_guardrails/nemo-rails-configmap.yaml actions.py snapshot is stale; run 'make update-nemo-configmap'.\n"
        )
        sys.exit(1)

# 4. Lula manifest README count parity (matches ci.yml lula-ai600-validation)
lula_dir = pathlib.Path("compliance/lula")
lula_readme = lula_dir / "README.md"
if lula_dir.is_dir() and lula_readme.is_file():
    disk_count = len(list(lula_dir.glob("lula-validation-*.yaml")))
    readme_names = set(
        re.findall(r"lula-validation-[a-z0-9_-]*\.yaml", lula_readme.read_text(encoding="utf-8"))
    )
    if disk_count != len(readme_names):
        sys.stderr.write(
            f"pre-commit: compliance/lula manifest count ({disk_count}) != README unique references ({len(readme_names)}).\n"
        )
        sys.exit(1)
PY
HOOK

chmod +x "${PRECOMMIT_FILE}"

echo "→ Installing commit-msg hook (Conventional Commits lint)..."
HOOK_FILE="$(resolve_hook_target commit-msg)"
cat > "${HOOK_FILE}" << 'HOOK'
#!/usr/bin/env bash
# Enforce Conventional Commits format
COMMIT_MSG_FILE="$1"
COMMIT_MSG=$(cat "$COMMIT_MSG_FILE")

# Strip comment lines
SUBJECT=$(echo "$COMMIT_MSG" | grep -v '^#' | head -1)

# Allow empty (amend with no message change) and merge commits
if [[ -z "$SUBJECT" ]] || echo "$SUBJECT" | grep -qE '^Merge '; then
  exit 0
fi

PATTERN='^(feat|fix|docs|style|refactor|perf|test|chore|ci|revert)(\([a-z0-9/_-]+\))?(!)?: .{1,72}$'

if ! echo "$SUBJECT" | grep -qE "$PATTERN"; then
  echo ""
  echo "❌  Commit message does not follow Conventional Commits format."
  echo ""
  echo "    Expected: <type>(<scope>): <description>"
  echo "    Types:    feat | fix | docs | style | refactor | perf | test | chore | ci | revert"
  echo "    Example:  feat(gateway): add Redis rate limiter"
  echo ""
  echo "    Your subject line was:"
  echo "    → $SUBJECT"
  echo ""
  exit 1
fi

# Warn if subject line exceeds 72 chars
LENGTH=${#SUBJECT}
if [[ $LENGTH -gt 72 ]]; then
  echo "⚠️   Subject line is ${LENGTH} chars (recommended ≤72)."
fi

exit 0
HOOK

chmod +x "${HOOK_FILE}"

echo "→ Installing pre-push hook (block pushes to protected branches + validate pushed branch names)..."
PREPUSH_FILE="$(resolve_hook_target pre-push)"
cat > "${PREPUSH_FILE}" << 'HOOK'
#!/usr/bin/env bash
# Refuse a push that updates or deletes a protected branch, and a branch push
# whose remote name breaks the naming convention (per AGENTS.md).
#
# Git writes one line per ref it is about to update to stdin:
#   <local ref> <local object name> <remote ref> <remote object name>
# Both checks read the remote ref, never the checked-out branch, so
# `git push origin HEAD:main` is refused from a feature branch and
# `git push origin v3.3.0` is allowed from main. Only refs/heads/* is checked:
# tags and other refs pass.
set -uo pipefail

PROTECTED_BRANCHES="main"

# Standard: (type)/(description). Hotfix: hotfix/(version)-(description).
# Same pattern as the Branch Name Validator job in .github/workflows/ci.yml,
# which also admits the dependabot/* branches GitHub creates.
PATTERN='^(feat|fix|docs|refactor|ci|test|chore|spike)/[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?$|^hotfix/v?[0-9]+\.[0-9]+\.[0-9]+-[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?$'

refuse_protected() {
  echo ""
  echo "❌  Direct push to '$1' is not allowed."
  echo "    Please create a feature branch and open a pull request:"
  echo "    git checkout -b feat/<your-feature>"
  echo ""
}

refuse_name() {
  echo ""
  echo "❌  Branch name '$1' does not follow the project's naming convention."
  echo "    See AGENTS.md for full rules. Valid patterns:"
  echo ""
  echo "    feat/<desc>     — new feature"
  echo "    fix/<desc>      — bug fix"
  echo "    docs/<desc>     — documentation"
  echo "    refactor/<desc> — code restructuring"
  echo "    ci/<desc>       — CI/CD changes"
  echo "    test/<desc>     — test additions"
  echo "    chore/<desc>    — maintenance"
  echo "    hotfix/<ver>-<desc> — production hotfix"
  echo "    spike/<desc>    — experiment"
  echo ""
  echo "    Where <desc> is lowercase kebab-case, ≤30 chars, no underscores."
  echo ""
  echo "    To fix: git branch -m <type>/<description>, then push again."
  echo ""
}

status=0
while read -r _local_ref local_oid remote_ref _remote_oid; do
  case "$remote_ref" in
    refs/heads/*) branch="${remote_ref#refs/heads/}" ;;
    *) continue ;;
  esac

  # Check 1: a protected branch is never updated, created or deleted by a push.
  for protected in $PROTECTED_BRANCHES; do
    if [[ "$branch" == "$protected" ]]; then
      refuse_protected "$branch"
      status=1
      continue 2
    fi
  done

  # A deletion (all-zero local object name) creates no branch to name-check.
  if [[ -z "${local_oid//0/}" ]]; then
    continue
  fi

  # Check 2: the branch name the remote will hold.
  if ! printf '%s\n' "$branch" | grep -qE "$PATTERN"; then
    refuse_name "$branch"
    status=1
  fi
done

exit "$status"
HOOK

chmod +x "${PREPUSH_FILE}"

echo ""
echo "✅  Git hooks installed successfully."
echo "    commit.template        → .gitmessage"
echo "    ${PRECOMMIT_FILE} → Ruff, mypy, and deterministic CI gates"
echo "    ${HOOK_FILE} → Conventional Commits lint"
echo "    ${PREPUSH_FILE}  → Protected branch guard + branch name validator"
echo ""
echo "    Run 'git commit' to see the template."
echo "    The pre-push hook refuses pushes to main and checks the name of every"
echo "    branch you push, whichever branch is checked out. Tags are not checked."
