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

"""One reader of ``CAGE_DEPLOYMENT_REGION``, and it fails closed.

``resolve_deployment_region()`` in ``src/gateway/governance/env_posture.py``
refuses a value that is not a supported region, and an unset one in an
enforcing posture. That holds only while nothing else reads the variable:
before it, thirty sites read it directly with four different fallbacks
(``US_FED``, an empty string, ``LOCAL`` and none), so one unknown value put
different controls in one process under different regions.

The gate walks every Python file under ``src/``, ``scripts/`` and
``packages/`` and fails on, outside ``env_posture.py``:

1. the string ``CAGE_DEPLOYMENT_REGION`` used as a value, including one
   folded from ``+``-joined string constants (docstrings, comments and longer
   messages that mention the name are prose, not reads);
2. any use of the name ``REGION_ENV_VAR``, the way to name the variable
   without writing the string.

It reads names, not values: a name assembled at run time from variables or an
encoding is out of its reach, the limit ``POAM-2026-214`` records for command
guards.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import Path

import pytest

from src.gateway.governance import env_posture
from src.gateway.governance.env_posture import (
    PERMISSIVE_DEFAULT_REGION,
    REGION_ENV_VAR,
    SUPPORTED_REGIONS,
    DeploymentRegionError,
    resolve_deployment_region,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
SCANNED_TREES = ("src", "scripts", "packages")
READER = Path("src/gateway/governance/env_posture.py")
VAR_NAME = "CAGE_DEPLOYMENT_REGION"
NAME_CONSTANT = "REGION_ENV_VAR"
#: The scanned trees hold well over this many Python files; a scan that finds
#: fewer is reading the wrong place and would pass on nothing.
MIN_SCANNED_FILES = 300


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


def _folded_str(node: ast.AST) -> str | None:
    """The value of a string constant, or of ``+``-joined string constants."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _folded_str(node.left), _folded_str(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _region_reads(path: Path, display: str) -> list[str]:
    """Describe each way *path* names ``CAGE_DEPLOYMENT_REGION`` as a value."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    # A statement that is only a string (a docstring) is prose, not a value.
    prose = {
        id(stmt.value)
        for stmt in ast.walk(tree)
        if isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, str)
    }
    findings: list[str] = []
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.Constant | ast.BinOp) and id(node) not in prose:
            if _folded_str(node) == VAR_NAME:
                findings.append(f"{display}:{line}: the string {VAR_NAME!r}")
        elif isinstance(node, ast.Name) and node.id == NAME_CONSTANT:
            findings.append(f"{display}:{line}: the name {NAME_CONSTANT}")
        elif isinstance(node, ast.Attribute) and node.attr == NAME_CONSTANT:
            findings.append(f"{display}:{line}: the attribute .{NAME_CONSTANT}")
        elif isinstance(node, ast.ImportFrom):
            findings.extend(
                f"{display}:{line}: an import of {NAME_CONSTANT}"
                for alias in node.names
                if alias.name == NAME_CONSTANT
            )
    return findings


def find_region_reads(root: Path, files: Iterable[Path]) -> list[str]:
    """Every read of the region outside the reader, across *files* under *root*."""
    findings: list[str] = []
    for path in files:
        rel = path.relative_to(root)
        if rel == READER:
            continue
        findings.extend(_region_reads(path, rel.as_posix()))
    return findings


def _python_files(root: Path) -> list[Path]:
    return sorted(
        path
        for tree in SCANNED_TREES
        if (root / tree).is_dir()
        for path in (root / tree).rglob("*.py")
        if "__pycache__" not in path.parts
    )


def test_resolve_deployment_region_is_the_only_reader() -> None:
    files = _python_files(REPO_ROOT)
    assert len(files) >= MIN_SCANNED_FILES, len(files)
    assert find_region_reads(REPO_ROOT, files) == []


def test_the_reader_named_by_the_gate_reads_the_variable() -> None:
    """An allowlist entry for a file that no longer reads the variable is stale."""
    reader = REPO_ROOT / READER
    assert f'{NAME_CONSTANT} = "{VAR_NAME}"' in reader.read_text(encoding="utf-8")
    assert env_posture.REGION_ENV_VAR == VAR_NAME


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            f'import os\nregion = os.environ.get("{VAR_NAME}", "US_FED")\n', id="get"
        ),
        pytest.param(f'import os\nregion = os.getenv("{VAR_NAME}")\n', id="getenv"),
        pytest.param(f'import os\nregion = os.environ["{VAR_NAME}"]\n', id="subscript"),
        pytest.param(
            f'import os\nset_ = "{VAR_NAME}" in os.environ\n', id="membership"
        ),
        pytest.param(f'KEY = "{VAR_NAME}"\n', id="aliased-constant"),
        pytest.param(
            'import os\nregion = os.environ.get("CAGE_" + "DEPLOYMENT_REGION")\n',
            id="joined-constants",
        ),
        pytest.param(
            "import os\n"
            f"from src.gateway.governance.env_posture import {NAME_CONSTANT}\n"
            f"region = os.environ.get({NAME_CONSTANT})\n",
            id="imported-name",
        ),
        pytest.param(
            "import os\nfrom src.gateway.governance import env_posture\n"
            f"region = os.getenv(env_posture.{NAME_CONSTANT})\n",
            id="module-attribute",
        ),
    ],
)
def test_planted_read_is_found(tmp_path: Path, source: str) -> None:
    planted = tmp_path / "src" / "planted.py"
    planted.parent.mkdir()
    planted.write_text(source, encoding="utf-8")
    findings = find_region_reads(tmp_path, [planted])
    assert findings, source
    assert all(f.startswith("src/planted.py:") for f in findings)


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(f'"""Reads {VAR_NAME} through the resolver."""\n', id="docstring"),
        pytest.param(f"# {VAR_NAME} is read in env_posture.py\nx = 1\n", id="comment"),
        pytest.param(
            f'MESSAGE = "Set {VAR_NAME} to one of US_FED, EU_ECB, APAC_MAS"\n',
            id="longer-message",
        ),
        pytest.param(
            f'def f():\n    """Uses {VAR_NAME}."""\n    return 1\n',
            id="function-docstring",
        ),
    ],
)
def test_prose_naming_the_variable_is_not_a_read(tmp_path: Path, source: str) -> None:
    planted = tmp_path / "src" / "prose.py"
    planted.parent.mkdir()
    planted.write_text(source, encoding="utf-8")
    assert find_region_reads(tmp_path, [planted]) == []


def test_the_reader_itself_is_exempt(tmp_path: Path) -> None:
    reader = tmp_path / READER
    reader.parent.mkdir(parents=True)
    reader.write_text(
        f'import os\n{NAME_CONSTANT} = "{VAR_NAME}"\nos.environ.get({NAME_CONSTANT})\n',
        encoding="utf-8",
    )
    assert find_region_reads(tmp_path, [reader]) == []


# ---------------------------------------------------------------------------
# What the reader accepts
# ---------------------------------------------------------------------------

PERMISSIVE = ("dev", "test", "ci")
ENFORCING = ("production", "staging", "local", "an-unknown-posture")


def test_supported_regions_match_the_jurisdiction_and_profile_tables() -> None:
    from src.gateway.governance.jurisdiction.registry import JURISDICTIONS
    from src.gateway.governance.oscal_ssp_exporter import REGIONAL_PROFILES

    assert set(JURISDICTIONS) == SUPPORTED_REGIONS
    assert set(REGIONAL_PROFILES) == SUPPORTED_REGIONS
    assert PERMISSIVE_DEFAULT_REGION in SUPPORTED_REGIONS


@pytest.mark.parametrize("posture", PERMISSIVE + ENFORCING)
@pytest.mark.parametrize("region", sorted(SUPPORTED_REGIONS))
def test_a_supported_region_is_returned_in_every_posture(
    region: str, posture: str
) -> None:
    env = {"CAGE_ENV": posture, VAR_NAME: f"  {region}\n"}
    assert resolve_deployment_region(env) == region


@pytest.mark.parametrize("posture", PERMISSIVE + ENFORCING)
@pytest.mark.parametrize("value", ["us_fed", "Eu_Ecb", "LOCAL", "US-FED", "EU", "*"])
def test_an_unsupported_value_is_refused_in_every_posture(
    value: str, posture: str
) -> None:
    with pytest.raises(DeploymentRegionError, match="not a supported region"):
        resolve_deployment_region({"CAGE_ENV": posture, VAR_NAME: value})


@pytest.mark.parametrize("value", [None, "", "   "])
@pytest.mark.parametrize("posture", PERMISSIVE)
def test_unset_runs_permissive_postures_under_the_default(
    posture: str, value: str | None
) -> None:
    env = {"CAGE_ENV": posture}
    if value is not None:
        env[VAR_NAME] = value
    assert resolve_deployment_region(env) == PERMISSIVE_DEFAULT_REGION


@pytest.mark.parametrize("value", [None, "", "   "])
@pytest.mark.parametrize("posture", [*ENFORCING, None])
def test_unset_is_refused_in_enforcing_postures(
    posture: str | None, value: str | None
) -> None:
    """``None`` posture: an unset ``CAGE_ENV`` resolves to production."""
    env: dict[str, str] = {}
    if posture is not None:
        env["CAGE_ENV"] = posture
    if value is not None:
        env[VAR_NAME] = value
    with pytest.raises(DeploymentRegionError, match="is not set"):
        resolve_deployment_region(env)


def test_the_process_environment_is_read_when_no_mapping_is_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAGE_ENV", "production")
    monkeypatch.setenv(VAR_NAME, "APAC_MAS")
    assert resolve_deployment_region() == "APAC_MAS"
    monkeypatch.delenv(VAR_NAME)
    with pytest.raises(DeploymentRegionError):
        resolve_deployment_region()


# ---------------------------------------------------------------------------
# Callers that used to fall back now refuse
# ---------------------------------------------------------------------------


@pytest.fixture
def fresh_registry():
    """A ``ControlRegistry`` that loads on next use, restored to that state after."""
    from src.gateway.governance.constants import ControlRegistry

    ControlRegistry.reset_for_testing()
    yield ControlRegistry
    ControlRegistry.reset_for_testing()


def test_control_registry_refuses_an_unknown_region(fresh_registry) -> None:
    with pytest.raises(DeploymentRegionError, match="not a supported region"):
        fresh_registry.reconfigure("LOCAL")


def test_control_registry_refuses_an_unset_region_in_an_enforcing_posture(
    fresh_registry, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CAGE_ENV", "production")
    monkeypatch.delenv(VAR_NAME, raising=False)
    with pytest.raises(DeploymentRegionError, match="is not set"):
        fresh_registry()
    assert fresh_registry._instance is None


def test_control_registry_loads_the_resolved_region(
    fresh_registry, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(VAR_NAME, "EU_ECB")
    assert fresh_registry().active_region == "EU_ECB"


def test_regional_profile_refuses_a_region_without_one() -> None:
    from src.gateway.governance.oscal_ssp_exporter import get_regional_profile

    with pytest.raises(DeploymentRegionError, match="has no OSCAL profile"):
        get_regional_profile("LOCAL")


def test_export_refuses_an_unknown_region_instead_of_exporting_us_fed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.gateway.governance import oscal_ssp_exporter

    monkeypatch.setenv(VAR_NAME, "LOCAL")
    assert oscal_ssp_exporter.main(["--log-level", "ERROR", "export", "--check"]) == 2


def test_envelope_region_is_resolved_when_built_not_at_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.gateway.governance.governance_envelope import (
        GovernanceContext,
        IssuerMetadata,
    )

    for region in ("EU_ECB", "APAC_MAS"):
        monkeypatch.setenv(VAR_NAME, region)
        assert IssuerMetadata().region == region
        assert GovernanceContext(policy_version="v").deployment_region == region
    monkeypatch.setenv(VAR_NAME, "LOCAL")
    with pytest.raises(DeploymentRegionError):
        IssuerMetadata()
