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

PY_HEADER='# Copyright 2026 Google LLC
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
'

YAML_HEADER='# Copyright 2026 Google LLC
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
'

CHECK_MODE=false
[[ "${1:-}" == "--check" ]] && CHECK_MODE=true

MISSING=()

prepend_header() {
  local file="$1"
  local header="$2"
  if grep -q "Apache License" "$file" 2>/dev/null; then
    return 0  # already has header — skip (idempotent)
  fi
  if $CHECK_MODE; then
    MISSING+=("$file")
    return 0
  fi
  local tmp
  tmp=$(mktemp)
  printf '%s\n' "$header" > "$tmp"
  cat "$file" >> "$tmp"
  mv "$tmp" "$file"
  echo "  [added] $file"
}

echo "Scanning for Python files missing Apache 2.0 header..."
while IFS= read -r -d '' f; do
  prepend_header "$f" "$PY_HEADER"
done < <(grep -rLZ "Apache License" --include="*.py" \
  --exclude-dir=".venv" --exclude-dir="__pycache__" --exclude-dir=".git" . 2>/dev/null)

echo "Scanning for YAML/YML files missing Apache 2.0 header..."
while IFS= read -r -d '' f; do
  prepend_header "$f" "$YAML_HEADER"
done < <(grep -rLZ "Apache License" --include="*.yaml" --include="*.yml" \
  --exclude-dir=".venv" --exclude-dir=".git" . 2>/dev/null)

if $CHECK_MODE; then
  if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "ERROR: ${#MISSING[@]} file(s) missing Apache 2.0 license header:"
    printf '  %s\n' "${MISSING[@]}"
    exit 1
  else
    echo "OK: All scanned files have Apache 2.0 license headers."
  fi
else
  echo "Done. All files processed."
fi
