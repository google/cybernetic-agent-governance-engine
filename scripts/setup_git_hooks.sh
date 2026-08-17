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

echo "→ Installing pre-push hook (block direct push to protected branches)..."
PREPUSH_FILE="${REPO_ROOT}/.git/hooks/pre-push"
cat > "${PREPUSH_FILE}" << 'HOOK'
#!/usr/bin/env bash
# Block direct pushes to protected branches
PROTECTED_BRANCHES="main"
CURRENT_BRANCH=$(git symbolic-ref HEAD 2>/dev/null | sed 's|refs/heads/||')

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
exit 0
HOOK

chmod +x "${PREPUSH_FILE}"

echo ""
echo "✅  Git hooks installed successfully."
echo "    commit.template → .gitmessage"
echo "    .git/hooks/commit-msg → Conventional Commits lint"
echo "    .git/hooks/pre-push  → Protected branch guard"
echo ""
echo "    Run 'git commit' to see the template."
