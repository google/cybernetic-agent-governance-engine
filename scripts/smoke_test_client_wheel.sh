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

# Two-phase built-wheel smoke gate for packages/cage-client:
#   Phase 1 (bare wheel, zero optional extras): proves `import cage_client` and
#   the core standalone suite succeed with no `langgraph` / `langchain_core`
#   installed anywhere in the environment.
#   Phase 2 (`[langgraph]` extra): proves the optional extra resolves and the
#   full standalone + LangGraph + SC-23 test suite passes against the built wheel.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT/packages/cage-client"

rm -rf dist
uv build

CLIENT_VERSION="$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
WHEEL_PATH="dist/cage_client-${CLIENT_VERSION}-py3-none-any.whl"
SMOKE_TMP="$(mktemp -d)"
SMOKE_VENV="${SMOKE_TMP}/wheel-venv"
cleanup() {
  rm -rf "$SMOKE_TMP"
}
trap cleanup EXIT

echo "=== Phase 1: bare wheel smoke (${WHEEL_PATH}, zero optional extras) ==="
uv venv "$SMOKE_VENV"
uv pip install --python "$SMOKE_VENV/bin/python" "$WHEEL_PATH" pytest
SMOKE_VENV="$SMOKE_VENV" CLIENT_VERSION="$CLIENT_VERSION" "$SMOKE_VENV/bin/python" -I - <<'EOF'
import importlib.util
import os
import pathlib
import sys

import cage_client

expected_version = os.environ["CLIENT_VERSION"]
smoke_venv = pathlib.Path(os.environ["SMOKE_VENV"]).resolve()
pkg_file = pathlib.Path(cage_client.__file__).resolve()

assert cage_client.__version__ == expected_version, cage_client.__version__
assert smoke_venv in pkg_file.parents, (
    f"cage_client loaded from {pkg_file}, expected inside {smoke_venv}"
)
for optional_mod in ("langgraph", "langchain_core"):
    assert importlib.util.find_spec(optional_mod) is None, (
        f"bare wheel environment unexpectedly resolved optional dependency {optional_mod!r}"
    )
    assert optional_mod not in sys.modules, (
        f"import cage_client unexpectedly loaded {optional_mod!r}"
    )
assert "cage_client.langgraph" not in sys.modules, (
    "import cage_client unexpectedly loaded cage_client.langgraph at top level"
)
print(f"Verified bare wheel: {pkg_file} version={cage_client.__version__}")
EOF
"$SMOKE_VENV/bin/pytest" tests/test_cage_client_standalone.py -v -o addopts="" -W ignore::pytest.PytestUnknownMarkWarning

echo "=== Phase 2: [langgraph] extra smoke (${WHEEL_PATH}[langgraph]) ==="
uv pip install --python "$SMOKE_VENV/bin/python" "${WHEEL_PATH}[langgraph]"
"$SMOKE_VENV/bin/pytest" tests/ -v -o addopts="" -W ignore::pytest.PytestUnknownMarkWarning
