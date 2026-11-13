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

"""Unit tests for ``scripts/check_client_sdk_sync.py`` standalone wheel & mirror-retirement gate."""

from __future__ import annotations

from pathlib import Path

import pytest

import scripts.check_client_sdk_sync as sdk_gate

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _make_fake_repo(
    tmp_path: Path,
    *,
    wheel_url: str = "https://example.com/releases/download/client-v0.3.0/cage_client-0.3.0-py3-none-any.whl",
    include_py_typed: bool = True,
    recreate_retired_mirror: bool = False,
) -> Path:
    pkg = tmp_path / "packages" / "cage-client" / "src" / "cage_client"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(
        "import json\nfrom .core import CageClient\n__all__ = ['CageClient']\n",
        encoding="utf-8",
    )
    (pkg / "core.py").write_text(
        "import httpx\nclass CageClient:\n    pass\n",
        encoding="utf-8",
    )
    if include_py_typed:
        (pkg / "py.typed").write_text("", encoding="utf-8")
    if recreate_retired_mirror:
        mirror = tmp_path / "src" / "gateway" / "client"
        mirror.mkdir(parents=True)
        (mirror / "__init__.py").write_text("# stale mirror\n", encoding="utf-8")

    advisor = (
        tmp_path
        / "src"
        / "governed_financial_advisor"
        / "infrastructure"
        / "gateway_client.py"
    )
    advisor.parent.mkdir(parents=True)
    advisor.write_text("from cage_client import CageClient\n", encoding="utf-8")

    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "demo"\nversion = "1.0.0"\n'
        f'[tool.uv.sources]\ncage-client = {{ url = "{wheel_url}" }}\n',
        encoding="utf-8",
    )
    return tmp_path


def test_real_repository_passes_with_zero_violations() -> None:
    """Live repository passes standalone wheel & mirror-retirement checks."""
    assert sdk_gate.main(["--verbose"]) == 0


def test_fails_when_retired_mirror_reappears(tmp_path: Path) -> None:
    """Recreating src/gateway/client/ fails closed."""
    repo = _make_fake_repo(tmp_path, recreate_retired_mirror=True)
    errors = sdk_gate.wheel_and_retirement_violations(repo)
    assert any("src/gateway/client exists" in err for err in errors)


def test_stale_bytecode_alone_does_not_revive_the_mirror(tmp_path: Path) -> None:
    """__pycache__ left by an earlier checkout is not importable and passes."""
    repo = _make_fake_repo(tmp_path)
    cache = repo / "src" / "gateway" / "client" / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "core.cpython-312.pyc").write_bytes(b"\x00")
    assert sdk_gate.wheel_and_retirement_violations(repo) == []


def test_fails_when_the_advisor_stops_importing_the_wheel(tmp_path: Path) -> None:
    """The advisor's GatewayClient must import cage_client."""
    repo = _make_fake_repo(tmp_path)
    (
        repo
        / "src"
        / "governed_financial_advisor"
        / "infrastructure"
        / "gateway_client.py"
    ).write_text("import httpx\n", encoding="utf-8")
    errors = sdk_gate.wheel_and_retirement_violations(repo)
    assert any("must import 'cage_client'" in err for err in errors)


def test_fails_when_py_typed_missing(tmp_path: Path) -> None:
    """Missing PEP 561 py.typed marker in packages/cage-client fails closed."""
    repo = _make_fake_repo(tmp_path, include_py_typed=False)
    errors = sdk_gate.wheel_and_retirement_violations(repo)
    assert any("py.typed is missing" in err for err in errors)


def test_fails_when_pyproject_uses_local_path_instead_of_wheel(tmp_path: Path) -> None:
    """Binding cage-client to a local path rather than a built .whl URL fails closed."""
    repo = _make_fake_repo(tmp_path)
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "1.0.0"\n'
        '[tool.uv.sources]\ncage-client = { path = "packages/cage-client" }\n',
        encoding="utf-8",
    )
    errors = sdk_gate.wheel_and_retirement_violations(repo)
    assert any("must pin a built .whl URL" in err for err in errors)
    assert any("must not use a local path source" in err for err in errors)


def test_fails_when_package_imports_monorepo_src_or_proof(tmp_path: Path) -> None:
    """Importing src.* or proof.* inside packages/cage-client fails closed."""
    repo = _make_fake_repo(tmp_path)
    pkg = repo / "packages" / "cage-client" / "src" / "cage_client"
    (pkg / "leak.py").write_text(
        "from src.gateway.governance.decisions import GovernanceDecision\n",
        encoding="utf-8",
    )
    pkg_errors = sdk_gate.import_violations(pkg, display_base=repo)
    assert any(
        "imports 'src.gateway.governance.decisions'" in err for err in pkg_errors
    )


def test_fails_when_src_imports_retired_gateway_client(tmp_path: Path) -> None:
    """Importing src.gateway.client anywhere under src/ or examples/ fails closed."""
    repo = _make_fake_repo(tmp_path)
    ex = repo / "examples"
    ex.mkdir()
    (ex / "demo.py").write_text(
        "from src.gateway.client.core import CageClient\n", encoding="utf-8"
    )
    errors = sdk_gate.wheel_and_retirement_violations(repo)
    assert any(
        "imports retired mirror 'src.gateway.client.core'" in err for err in errors
    )


def test_fails_when_package_version_drifts_from_pinned_wheel_url(
    tmp_path: Path,
) -> None:
    """Bumping packages/cage-client/pyproject.toml without updating the pinned wheel fails closed."""
    repo = _make_fake_repo(tmp_path)
    pkg_pyproject = repo / "packages" / "cage-client" / "pyproject.toml"
    pkg_pyproject.write_text(
        '[project]\nname = "cage-client"\nversion = "0.4.0"\n',
        encoding="utf-8",
    )
    errors = sdk_gate.wheel_and_retirement_violations(repo)
    assert any("version '0.4.0' does not match pinned wheel" in err for err in errors)


def test_installed_wheel_parity_passes_on_matching_tree_and_fails_on_drift(
    tmp_path: Path,
) -> None:
    """installed_wheel_parity_violations verifies SHA-256 parity against site-packages/cage_client."""
    repo = _make_fake_repo(tmp_path / "repo")
    pkg = repo / "packages" / "cage-client" / "src" / "cage_client"
    wheel_dir = tmp_path / "site-packages" / "cage_client"
    wheel_dir.mkdir(parents=True)
    for rel, src_path in sdk_gate.collect_files(pkg).items():
        dst = wheel_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src_path.read_bytes())

    assert sdk_gate.installed_wheel_parity_violations(pkg, wheel_dir) == []

    # Mutating working-tree source without cutting a new wheel fails closed
    (pkg / "core.py").write_text(
        "import httpx\nclass CageClient:\n    x = 1\n", encoding="utf-8"
    )
    drift_errors = sdk_gate.installed_wheel_parity_violations(pkg, wheel_dir)
    assert any(
        "diverges from installed cage-client wheel" in err for err in drift_errors
    )

    # Extra file in working tree missing from wheel fails closed
    (pkg / "extra.py").write_text("VALUE = 1\n", encoding="utf-8")
    missing_errors = sdk_gate.installed_wheel_parity_violations(pkg, wheel_dir)
    assert any(
        "missing from installed cage-client wheel" in err for err in missing_errors
    )
