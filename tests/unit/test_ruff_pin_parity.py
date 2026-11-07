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

"""Verify ruff version pin parity across pyproject.toml, uv.lock, and CI workflows,
plus CVE-2026-49272 floor on oauthlib."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 (requires-python admits it)
    import tomli as tomllib  # type: ignore[no-redef]

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
UV_LOCK_PATH = REPO_ROOT / "uv.lock"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"


def _locked_package_version(lock_data: dict, name: str) -> str:
    for pkg in lock_data.get("package", []):
        if pkg.get("name") == name:
            return str(pkg["version"])
    raise AssertionError(f"Package {name!r} missing from uv.lock")


def test_ruff_exact_pin_matches_uv_lock_and_ci_workflows() -> None:
    pyproject = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    lock_data = tomllib.loads(UV_LOCK_PATH.read_text(encoding="utf-8"))

    locked_ruff = _locked_package_version(lock_data, "ruff")
    lint_deps = pyproject["project"]["optional-dependencies"]["lint"]
    assert f"ruff=={locked_ruff}" in lint_deps, (
        f"pyproject.toml [project.optional-dependencies.lint] must pin exact "
        f"ruff=={locked_ruff} matching uv.lock (got {lint_deps!r})"
    )

    ci_yml = (WORKFLOWS_DIR / "ci.yml").read_text(encoding="utf-8")
    assert "uv sync --locked --all-groups --all-extras" in ci_yml
    assert f'"ruff=={locked_ruff}"' in ci_yml

    unpinned_pip_ruff = re.compile(r"\bpip\s+install\b[^\n]*\bruff(?!==)")
    for wf in sorted(WORKFLOWS_DIR.glob("*.yml")):
        text = wf.read_text(encoding="utf-8")
        assert not unpinned_pip_ruff.search(text), (
            f"{wf.name} contains an unpinned `pip install ... ruff`; "
            f'pin to "ruff=={locked_ruff}"'
        )


def test_oauthlib_locked_above_cve_2026_49272() -> None:
    pyproject = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    constraints = (
        pyproject.get("tool", {}).get("uv", {}).get("constraint-dependencies", [])
    )
    assert any(c.startswith("oauthlib>=4.0.1") for c in constraints), (
        "pyproject.toml [tool.uv].constraint-dependencies must enforce oauthlib>=4.0.1"
    )

    lock_data = tomllib.loads(UV_LOCK_PATH.read_text(encoding="utf-8"))
    locked_oauthlib = _locked_package_version(lock_data, "oauthlib")
    parts = tuple(int(p) for p in locked_oauthlib.split(".")[:3])
    assert parts >= (4, 0, 1), (
        f"uv.lock resolves vulnerable oauthlib=={locked_oauthlib} (CVE-2026-49272)"
    )
