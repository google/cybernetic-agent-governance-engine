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

echo "→ Installing commit message template..."
git config commit.template "${REPO_ROOT}/.gitmessage"

echo "→ Installing commit-msg hook (Conventional Commits lint)..."
HOOK_FILE="${REPO_ROOT}/.git/hooks/commit-msg"
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

echo "→ Installing pre-push hook (block direct push to protected branches + validate branch names)..."
PREPUSH_FILE="${REPO_ROOT}/.git/hooks/pre-push"
cat > "${PREPUSH_FILE}" << 'HOOK'
#!/usr/bin/env bash
# Block direct pushes to protected branches and validate branch names
PROTECTED_BRANCHES="main"
CURRENT_BRANCH=$(git symbolic-ref HEAD 2>/dev/null | sed 's|refs/heads/||')

# Check 1: Block direct push to protected branches
for BRANCH in $PROTECTED_BRANCHES; do
  if [[ "$CURRENT_BRANCH" == "$BRANCH" ]]; then
    echo ""
    echo "❌  Direct push to '$BRANCH' is not allowed."
    echo "    Please create a feature branch and open a pull request:"
    echo "    git checkout -b feat/<your-feature>"
    echo ""
    exit 1
  fi
done

# Check 2: Validate branch name (per AGENTS.md)
# Hotfix has different structure (version-desc), so use alternation:
# Standard: (type)/(description)
# Hotfix:   hotfix/(version)-(description)
PATTERN='^(feat|fix|docs|refactor|ci|test|chore|spike)/[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?$|^hotfix/v?[0-9]+\.[0-9]+\.[0-9]+-[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?$'

if ! echo "$CURRENT_BRANCH" | grep -qE "$PATTERN"; then
  echo ""
  echo "❌  Branch name '$CURRENT_BRANCH' does not follow the project's naming convention."
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
  echo "    To fix: git checkout -b <type>/<description>"
  echo ""
  exit 1
fi

exit 0
HOOK

chmod +x "${PREPUSH_FILE}"

echo ""
echo "✅  Git hooks installed successfully."
echo "    commit.template → .gitmessage"
echo "    .git/hooks/commit-msg → Conventional Commits lint"
echo "    .git/hooks/pre-push  → Protected branch guard + branch name validator"
echo ""
echo "    Run 'git commit' to see the template."
echo "    The pre-push hook will validate your branch name before pushing."
