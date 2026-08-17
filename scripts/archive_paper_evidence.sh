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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

die() { echo "ERROR: $*" >&2; exit 1; }

sha256() {
    local file="$1"
    if command -v sha256sum &>/dev/null; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        die "Neither sha256sum nor shasum found. Install one and retry."
    fi
}

# ---------------------------------------------------------------------------
# Resolve repo root (script may be called from any directory)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Verify we are inside a git repo and collect identity fields
# ---------------------------------------------------------------------------

cd "$REPO_ROOT"

git rev-parse --git-dir &>/dev/null || die "Not inside a git repository."

SHORT_SHA="$(git rev-parse --short HEAD)"
FULL_SHA="$(git rev-parse HEAD)"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
NOW_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
DATE_PREFIX="$(date -u '+%Y-%m-%d')"

# ---------------------------------------------------------------------------
# Locate source files
# ---------------------------------------------------------------------------

PAPER_JSON="/tmp/cage_paper_metrics.json"
PAPER_TXT="/tmp/cage_paper_metrics.txt"
RECON_JSON="/tmp/cage_reconciliation_metrics.json"
RECON_TXT="/tmp/cage_reconciliation_metrics.txt"

MISSING=()
[[ -f "$PAPER_JSON" ]] || MISSING+=("$PAPER_JSON")
[[ -f "$PAPER_TXT"  ]] || MISSING+=("$PAPER_TXT")

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "WARNING: The following files are missing and will be skipped:"
    for f in "${MISSING[@]}"; do echo "  $f"; done
    echo "  Run scripts/measure_paper_metrics.py first (Step B)."
fi

RECON_MISSING=()
[[ -f "$RECON_JSON" ]] || RECON_MISSING+=("$RECON_JSON")
[[ -f "$RECON_TXT"  ]] || RECON_MISSING+=("$RECON_TXT")

if [[ ${#RECON_MISSING[@]} -gt 0 ]]; then
    echo "WARNING: The following files are missing and will be skipped:"
    for f in "${RECON_MISSING[@]}"; do echo "  $f"; done
    echo "  Run scripts/measure_reconciliation_metrics.py first (Step C)."
fi

# Require at least one source file to be present
if [[ ${#MISSING[@]} -eq 4 && ${#RECON_MISSING[@]} -eq 4 ]]; then
    die "No measurement output files found in /tmp/. Run Steps B and/or C first."
fi

# ---------------------------------------------------------------------------
# Create destination directory
# ---------------------------------------------------------------------------

DEST_DIR="$REPO_ROOT/docs/paper/measurements/${DATE_PREFIX}-${SHORT_SHA}"

if [[ -d "$DEST_DIR" ]]; then
    echo "WARNING: Destination directory already exists: $DEST_DIR"
    echo "  Appending a counter suffix to avoid overwriting."
    COUNTER=1
    while [[ -d "${DEST_DIR}-${COUNTER}" ]]; do
        COUNTER=$((COUNTER + 1))
    done
    DEST_DIR="${DEST_DIR}-${COUNTER}"
fi

mkdir -p "$DEST_DIR"
echo "Archive directory: $DEST_DIR"

# ---------------------------------------------------------------------------
# Copy files and compute checksums
# ---------------------------------------------------------------------------

declare -A FILE_SHAS

copy_and_hash() {
    local src="$1"
    local name
    name="$(basename "$src")"
    if [[ -f "$src" ]]; then
        cp "$src" "$DEST_DIR/$name"
        FILE_SHAS["$name"]="$(sha256 "$DEST_DIR/$name")"
        echo "  Archived: $name  (sha256: ${FILE_SHAS[$name]})"
    else
        FILE_SHAS["$name"]="NOT PRESENT"
    fi
}

copy_and_hash "$PAPER_JSON"
copy_and_hash "$PAPER_TXT"
copy_and_hash "$RECON_JSON"
copy_and_hash "$RECON_TXT"

# ---------------------------------------------------------------------------
# Write PROVENANCE.md from template
# ---------------------------------------------------------------------------

TEMPLATE="$REPO_ROOT/docs/paper/measurements/PROVENANCE_TEMPLATE.md"
[[ -f "$TEMPLATE" ]] || die "Template not found: $TEMPLATE"

PROVENANCE="$DEST_DIR/PROVENANCE.md"
cp "$TEMPLATE" "$PROVENANCE"

# Substitute identity fields into the template using sed.
# The template uses HTML comment placeholders: <!-- e.g. ... -->
# We replace only the first occurrence of each placeholder pattern.

sed_inplace() {
    # Portable in-place sed for both GNU and BSD (macOS)
    if sed --version &>/dev/null 2>&1; then
        sed -i "$@"          # GNU sed
    else
        sed -i '' "$@"       # BSD sed (macOS)
    fi
}

sed_inplace "s|<!-- e.g. a1b2c3d4e5f6... -->|${FULL_SHA}|" "$PROVENANCE"
sed_inplace "s|<!-- e.g. a1b2c3d -->|${SHORT_SHA}|" "$PROVENANCE"
sed_inplace "s|<!-- e.g. docs\/paper-metrics-2026-08-01 -->|${BRANCH}|" "$PROVENANCE"
sed_inplace "s|<!-- e.g. 2026-08-01T14:32:00Z -->|${NOW_UTC}|" "$PROVENANCE"

# Inject file checksums
for fname in cage_paper_metrics.json cage_paper_metrics.txt \
             cage_reconciliation_metrics.json cage_reconciliation_metrics.txt; do
    sha="${FILE_SHAS[$fname]:-NOT PRESENT}"
    # Replace the placeholder on the line containing the filename
    sed_inplace "s|^\(| \`${fname}\` |.*sha256sum.*\$|\| \`${fname}\` | ${sha} |" "$PROVENANCE" 2>/dev/null || true
done

echo "  PROVENANCE.md written: $PROVENANCE"

# ---------------------------------------------------------------------------
# Print next steps
# ---------------------------------------------------------------------------

cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Archive complete: ${DEST_DIR}

NEXT STEP — Step E (human evaluation gate):
  Open ${PROVENANCE}
  Complete every gate in the "Step E" table.
  Sign off with your name and date.
  Only after all applicable gates PASS may you proceed to Step F.

See docs/paper/MEASUREMENT_RUNBOOK.md for the full procedure.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
