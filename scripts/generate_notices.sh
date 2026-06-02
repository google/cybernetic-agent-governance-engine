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

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_FILE="$REPO_ROOT/THIRD_PARTY_NOTICES.md"

echo "# Third-Party Notices" > "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "This project incorporates third-party software. Licenses and attributions follow." >> "$OUTPUT_FILE"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# ── Section 1: Root Python environment ──────────────────────────────────────
echo "## Python: Root Environment (pyproject.toml)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

cd "$REPO_ROOT"
# Use --no-install-project to skip building the local package (missing src/cybernetic_governance_engine/__init__.py)
uv sync --all-groups --no-install-project --quiet
# Use --no-project so uv doesn't try to build/install the project itself
uv run --no-project pip-licenses \
    --format=markdown \
    --with-urls \
    --with-authors \
    --order=license \
    >> "$OUTPUT_FILE"

echo "" >> "$OUTPUT_FILE"

# ── Section 2: compliance_bridge (consolidated into pyproject.toml) ─────────
echo "## Python: src/compliance_bridge (consolidated into pyproject.toml \`compliance\` extra)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "_Dependencies previously in src/compliance_bridge/requirements.txt have been absorbed into the root pyproject.toml \`compliance\` extra. Covered by Section 1._" >> "$OUTPUT_FILE"

echo "" >> "$OUTPUT_FILE"

# ── Section 3: governed_financial_advisor (consolidated into pyproject.toml) ─
echo "## Python: src/governed_financial_advisor (consolidated into pyproject.toml \`advisor\` extra)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "_Dependencies previously in src/governed_financial_advisor/requirements.txt have been absorbed into the root pyproject.toml \`advisor\` extra. Covered by Section 1._" >> "$OUTPUT_FILE"

echo "" >> "$OUTPUT_FILE"

# ── Section 4: Node.js (agentsight-ui) ──────────────────────────────────────
echo "## Node.js: src/agentsight-ui (package.json)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

if ! command -v node >/dev/null 2>&1; then
    echo "_Node.js not found — skipping agentsight-ui license scan._" >> "$OUTPUT_FILE"
else
    # Disable exit-on-error for the entire Node.js section so npm/npx errors
    # don't abort the script
    set +e
    cd "$REPO_ROOT/src/agentsight-ui"
    if [ ! -d node_modules ]; then
        npm install --silent 2>/dev/null
    fi

    NODE_LICENSES_TMP=$(mktemp -u /tmp/node-licenses-XXXXXX.txt)

    # generate-license-file cannot write to /dev/stdout — use a temp file
    # Note: mktemp -u so the file does not pre-exist (tool prompts for overwrite)
    npx --yes generate-license-file \
        --input package.json \
        --output "$NODE_LICENSES_TMP" \
        --eol lf \
        2>/dev/null
    NODE_EXIT=$?

    if [ $NODE_EXIT -eq 0 ] && [ -s "$NODE_LICENSES_TMP" ]; then
        cat "$NODE_LICENSES_TMP" >> "$OUTPUT_FILE"
    else
        # Fallback: license-checker
        npx --yes license-checker \
            --production \
            --markdown \
            >> "$OUTPUT_FILE" 2>/dev/null
        CHECKER_EXIT=$?
        if [ $CHECKER_EXIT -ne 0 ]; then
            echo "_Node.js license scan failed — skipped._" >> "$OUTPUT_FILE"
        fi
    fi

    rm -f "$NODE_LICENSES_TMP"
    set -e
fi

echo "" >> "$OUTPUT_FILE"
echo "---" >> "$OUTPUT_FILE"
echo "_End of Third-Party Notices_" >> "$OUTPUT_FILE"

cd "$REPO_ROOT"
echo "✅ THIRD_PARTY_NOTICES.md written to $OUTPUT_FILE"
