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
CURATED_NOTICES="$REPO_ROOT/THIRD_PARTY_NOTICES.md"
OUTPUT_FILE="${1:-${CAGE_NOTICES_RAW_OUT:-/tmp/cage-raw-licenses.md}}"

# Refuse to destructively clobber the curated THIRD_PARTY_NOTICES.md (which carries
# vendored source attributions, container base image notices, and usage notes).
if [ "$(cd "$(dirname "$OUTPUT_FILE")" 2>/dev/null && pwd)/$(basename "$OUTPUT_FILE")" = "$CURATED_NOTICES" ]; then
    echo "ERROR: Refusing to overwrite curated $CURATED_NOTICES directly." >&2
    echo "Write the raw license inventory to a scratch path (default: /tmp/cage-raw-licenses.md)" >&2
    echo "and reconcile changes per 'How to Update This File' in THIRD_PARTY_NOTICES.md." >&2
    exit 1
fi

echo "# Raw Third-Party License Inventory" > "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# ── Section 1: Root Python environment (all groups + all optional extras) ────
echo "## Python: Root Environment (pyproject.toml — --locked --all-groups --all-extras)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

cd "$REPO_ROOT"
uv sync --locked --all-groups --all-extras --no-install-project --quiet
uv run --no-sync --no-project pip-licenses \
    --format=markdown \
    --with-urls \
    --with-authors \
    --order=license \
    >> "$OUTPUT_FILE"

echo "" >> "$OUTPUT_FILE"

# ── Section 2: Node.js (agentsight-ui — offline package-lock.json parse) ─────
echo "## Node.js: src/agentsight-ui (package.json / package-lock.json)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

if [ -f "$REPO_ROOT/src/agentsight-ui/package-lock.json" ]; then
    uv run --no-sync --no-project python - "$REPO_ROOT/src/agentsight-ui/package.json" "$REPO_ROOT/src/agentsight-ui/package-lock.json" >> "$OUTPUT_FILE" <<'PY'
import json
import sys

pkg = json.load(open(sys.argv[1], encoding="utf-8"))
lock = json.load(open(sys.argv[2], encoding="utf-8"))
packages = lock.get("packages", {})

direct = {}
for section in ("dependencies", "devDependencies"):
    for name, spec in sorted((pkg.get(section) or {}).items()):
        direct[name] = (section, spec)

print("| Name | Scope | Spec | Pinned Version | License |")
print("| :--- | :--- | :--- | :--- | :--- |")
for name, (scope, spec) in sorted(direct.items()):
    meta = packages.get(f"node_modules/{name}", {})
    version = meta.get("version", "unknown")
    lic = meta.get("license", "unknown")
    print(f"| {name} | {scope} | {spec} | {version} | {lic} |")
PY
else
    echo "_package-lock.json not found — skipping agentsight-ui license scan._" >> "$OUTPUT_FILE"
fi

echo "" >> "$OUTPUT_FILE"
echo "---" >> "$OUTPUT_FILE"
echo "_End of Raw Third-Party License Inventory_" >> "$OUTPUT_FILE"

cd "$REPO_ROOT"
echo "✅ Raw license inventory written to $OUTPUT_FILE (reconcile against $CURATED_NOTICES)"
