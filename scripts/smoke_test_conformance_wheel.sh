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

# Two-phase built-wheel + sdist smoke gate for packages/cage-conformance:
#   Phase 1 (bare wheel & sdist, zero third-party deps): proves CLI entrypoints
#   (`verify --trace`, `diagnose-receipt`, `verify-report`) run using stdlib
#   only inside site-packages with zero `src` or `proof` leakage.
#   Phase 2 (`[attest]` extra): proves optional `cryptography` extra resolves
#   and `audience` / `verify-report` work cleanly.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT/packages/cage-conformance"

rm -rf dist
uv build

CONF_VERSION="$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
COMMIT_SHA="${COMMIT_SHA:-$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo 000000000000)}"
WHEEL_PATH="dist/cage_conformance-${CONF_VERSION}-py3-none-any.whl"
SDIST_PATH="dist/cage_conformance-${CONF_VERSION}.tar.gz"
SMOKE_TMP="$(mktemp -d)"
cleanup() {
  rm -rf "$SMOKE_TMP"
}
trap cleanup EXIT

echo "=== Phase 1a: bare wheel smoke (${WHEEL_PATH}, zero third-party deps) ==="
WHEEL_VENV="${SMOKE_TMP}/wheel-venv"
uv venv "$WHEEL_VENV"
uv pip install --python "$WHEEL_VENV/bin/python" --no-deps "$WHEEL_PATH"
"$WHEEL_VENV/bin/cage-conformance" --version | grep -Fx "${CONF_VERSION}"

WHEEL_VENV="$WHEEL_VENV" CONF_VERSION="$CONF_VERSION" "$WHEEL_VENV/bin/python" -I - <<'EOF'
import importlib.util
import os
import pathlib
import sys

import cage_conformance

expected_version = os.environ["CONF_VERSION"]
venv_root = pathlib.Path(os.environ["WHEEL_VENV"]).resolve()
pkg_file = pathlib.Path(cage_conformance.__file__).resolve()

assert cage_conformance.__version__ == expected_version, cage_conformance.__version__
assert venv_root in pkg_file.parents, (
    f"cage_conformance loaded from {pkg_file}, expected inside {venv_root}"
)
assert importlib.util.find_spec("cryptography") is None, (
    "bare wheel unexpectedly resolved cryptography"
)
leaked = sorted(m for m in sys.modules if m.split(".")[0] in {"src", "proof"})
assert not leaked, f"unexpected monorepo modules imported: {leaked}"
print(f"Verified bare wheel: {pkg_file} version={cage_conformance.__version__}")
EOF

REPORT_JSON="${SMOKE_TMP}/trace-report.json"
"$WHEEL_VENV/bin/cage-conformance" verify \
  --trace src/cage_conformance/vectors/trace_v1.json \
  --provider-id cage-conformance-wheel-smoke \
  --adapter-author-org "Google LLC" \
  --counterparty-org "Google LLC" \
  --adapter-version "$CONF_VERSION" \
  --adapter-commit "${COMMIT_SHA::12}" \
  --runner-org "Google LLC" \
  --runner-identity "ci-wheel-smoke@github-actions" \
  --output "$REPORT_JSON"
VERIFY_OUT="$("$WHEEL_VENV/bin/cage-conformance" verify-report "$REPORT_JSON")"
grep -q "conformant=True" <<<"$VERIFY_OUT"
"$WHEEL_VENV/bin/cage-conformance" diagnose-receipt \
  src/cage_conformance/vectors/actuator_01_readme_receipt.json >/dev/null

echo "=== Phase 1b: sdist smoke (${SDIST_PATH}) ==="
SDIST_VENV="${SMOKE_TMP}/sdist-venv"
uv venv "$SDIST_VENV"
uv pip install --python "$SDIST_VENV/bin/python" --no-deps "$SDIST_PATH"
"$SDIST_VENV/bin/cage-conformance" --version | grep -Fx "${CONF_VERSION}"
"$SDIST_VENV/bin/cage-conformance" verify \
  --trace src/cage_conformance/vectors/trace_v1.json \
  --provider-id cage-conformance-sdist-smoke \
  --adapter-author-org "Google LLC" \
  --counterparty-org "Google LLC" \
  --adapter-version "$CONF_VERSION" \
  --adapter-commit "${COMMIT_SHA::12}" \
  --runner-org "Google LLC" \
  --runner-identity "ci-sdist-smoke@github-actions" >/dev/null

echo "=== Phase 2: [attest] extra smoke (${WHEEL_PATH}[attest]) ==="
uv pip install --python "$WHEEL_VENV/bin/python" "${WHEEL_PATH}[attest]"
AUDIENCE_OUT="$("$WHEEL_VENV/bin/cage-conformance" audience "$REPORT_JSON")"
grep -q "^cage-conformance:sha256:" <<<"$AUDIENCE_OUT"
VERIFY_ATTEST_OUT="$("$WHEEL_VENV/bin/cage-conformance" verify-report "$REPORT_JSON")"
grep -q "conformant=True" <<<"$VERIFY_ATTEST_OUT"
