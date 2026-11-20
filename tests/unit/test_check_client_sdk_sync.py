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
    wheel_url: str | None = None,
    pkg_version: str = "0.4.0",
    release_status: str = "unreleased",
    editable: bool | None = False,
    include_py_typed: bool = True,
    recreate_retired_mirror: bool = False,
) -> Path:
    pkg_root = tmp_path / "packages" / "cage-client"
    pkg = pkg_root / "src" / "cage_client"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(
        f'import json\nfrom .core import CageClient\n__version__ = "{pkg_version}"\n__all__ = ["CageClient"]\n',
        encoding="utf-8",
    )
    (pkg / "core.py").write_text(
        "import httpx\nclass CageClient:\n    pass\n",
        encoding="utf-8",
    )
    if include_py_typed:
        (pkg / "py.typed").write_text("", encoding="utf-8")
    (pkg_root / "pyproject.toml").write_text(
        f'[project]\nname = "cage-client"\nversion = "{pkg_version}"\n'
        f'[tool.cage.release]\nstatus = "{release_status}"\n',
        encoding="utf-8",
    )
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

    if wheel_url is not None:
        source_line = f'cage-client = {{ url = "{wheel_url}" }}'
    elif editable is None:
        source_line = 'cage-client = { path = "packages/cage-client" }'
    else:
        source_line = f'cage-client = {{ path = "packages/cage-client", editable = {"true" if editable else "false"} }}'

    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "demo"\nversion = "1.0.0"\n'
        f'[dependency-groups]\ntest = ["cage-client=={pkg_version}"]\n'
        f'[project.optional-dependencies]\nadvisor = ["cage-client=={pkg_version}"]\n'
        f"[tool.uv.sources]\n{source_line}\n",
        encoding="utf-8",
    )
    return tmp_path


def test_real_repository_passes_with_zero_violations() -> None:
    """Live repository passes standalone wheel, release-state & mirror-retirement checks."""
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


def test_editable_path_source_fails_closed_while_non_editable_and_whl_url_pass(
    tmp_path: Path,
) -> None:
    """Editable path sources fail closed; editable=false and .whl URL both pass."""
    editable_repo = _make_fake_repo(tmp_path / "editable", editable=True)
    errors = sdk_gate.wheel_and_retirement_violations(editable_repo)
    assert any("editable = false" in err for err in errors)

    implicit_repo = _make_fake_repo(tmp_path / "implicit", editable=None)
    assert any(
        "editable = false" in err
        for err in sdk_gate.wheel_and_retirement_violations(implicit_repo)
    )

    wheel_repo = _make_fake_repo(
        tmp_path / "wheel",
        pkg_version="0.4.0",
        wheel_url="https://example.com/releases/download/client-v0.4.0/cage_client-0.4.0-py3-none-any.whl",
    )
    assert sdk_gate.wheel_and_retirement_violations(wheel_repo) == []

    non_editable_repo = _make_fake_repo(tmp_path / "noneditable", editable=False)
    assert sdk_gate.wheel_and_retirement_violations(non_editable_repo) == []


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


def test_fails_when_package_version_drifts_from_pinned_wheel_or_init(
    tmp_path: Path,
) -> None:
    """Version mismatch across packages/cage-client, __init__.py, or root pins fails closed."""
    repo = _make_fake_repo(
        tmp_path,
        pkg_version="0.3.0",
        wheel_url="https://example.com/releases/download/client-v0.3.0/cage_client-0.3.0-py3-none-any.whl",
    )
    pkg_pyproject = repo / "packages" / "cage-client" / "pyproject.toml"
    pkg_pyproject.write_text(
        '[project]\nname = "cage-client"\nversion = "0.4.0"\n'
        '[tool.cage.release]\nstatus = "unreleased"\n',
        encoding="utf-8",
    )
    errors = sdk_gate.wheel_and_retirement_violations(repo)
    assert any("version '0.4.0' does not match pinned wheel" in err for err in errors)
    assert any("__version__='0.3.0' does not match" in err for err in errors)
    assert any("pins cage-client==0.3.0" in err for err in errors)


def test_release_state_contract_prevents_vacuous_unreleased_window(
    tmp_path: Path,
) -> None:
    """Release-state gate enforces published tag+tree parity vs explicit unreleased > latest tag."""
    # 1. status="unreleased" with 0.4.0 > client-v0.3.0 and no client-v0.4.0 tag -> PASS
    repo = _make_fake_repo(
        tmp_path / "unrel_ok", pkg_version="0.4.0", release_status="unreleased"
    )
    assert (
        sdk_gate.release_state_violations(
            repo, git_tags=["client-v0.2.0", "client-v0.3.0"]
        )
        == []
    )

    # 2. status="unreleased" once client-v0.4.0 tag exists -> FAIL
    errs_tagged = sdk_gate.release_state_violations(
        repo, git_tags=["client-v0.3.0", "client-v0.4.0"]
    )
    assert any("already exists" in e for e in errs_tagged)

    # 3. status="unreleased" with version <= latest tag -> FAIL
    repo_old = _make_fake_repo(
        tmp_path / "unrel_old", pkg_version="0.3.0", release_status="unreleased"
    )
    errs_old = sdk_gate.release_state_violations(
        repo_old, git_tags=["client-v0.3.0", "client-v0.4.0"]
    )
    assert any("strictly greater" in e for e in errs_old)

    # 4. --cutting-release-tag client-v0.4.0 on status="unreleased" (even after tag created) -> PASS
    assert (
        sdk_gate.release_state_violations(
            repo,
            cutting_release_tag="client-v0.4.0",
            git_tags=["client-v0.3.0", "client-v0.4.0"],
        )
        == []
    )

    # 5. status="published" with missing tag -> FAIL (cannot declare version without release)
    repo_pub = _make_fake_repo(
        tmp_path / "pub", pkg_version="0.4.0", release_status="published"
    )
    errs_no_tag = sdk_gate.release_state_violations(
        repo_pub, git_tags=["client-v0.3.0"]
    )
    assert any("does not exist" in e for e in errs_no_tag)

    # 6. status="published" with matching tag + byte-identical tree -> PASS
    pkg_dir = repo_pub / "packages" / "cage-client" / "src" / "cage_client"
    matching_tree = {
        rel: full.read_bytes() for rel, full in sdk_gate.collect_files(pkg_dir).items()
    }
    assert (
        sdk_gate.release_state_violations(
            repo_pub,
            git_tags=["client-v0.3.0", "client-v0.4.0"],
            tagged_tree_files=matching_tree,
        )
        == []
    )

    # 7. status="published" with post-tag source modification -> FAIL
    (pkg_dir / "core.py").write_text(
        "import httpx\nclass CageClient:\n    drifted = True\n", encoding="utf-8"
    )
    errs_drift = sdk_gate.release_state_violations(
        repo_pub,
        git_tags=["client-v0.3.0", "client-v0.4.0"],
        tagged_tree_files=matching_tree,
    )
    assert any("diverges from published tag 'client-v0.4.0'" in e for e in errs_drift)

    # 8. Missing or unknown [tool.cage.release].status -> FAIL
    (repo_pub / "packages" / "cage-client" / "pyproject.toml").write_text(
        '[project]\nname = "cage-client"\nversion = "0.4.0"\n', encoding="utf-8"
    )
    errs_missing = sdk_gate.release_state_violations(
        repo_pub, git_tags=["client-v0.4.0"]
    )
    assert any("[tool.cage.release].status must be" in e for e in errs_missing)


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

    # Mutating working-tree source without rebuilding wheel fails closed
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


def test_read_tagged_package_files_handles_non_ascii_paths(tmp_path: Path) -> None:
    """_read_tagged_package_files uses git ls-tree -z so non-ASCII paths are not C-quoted."""
    import subprocess

    repo = _make_fake_repo(tmp_path, pkg_version="0.4.0", release_status="published")
    pkg = repo / "packages" / "cage-client" / "src" / "cage_client"
    non_ascii = pkg / "notes — utf8.txt"
    non_ascii.write_bytes(b"utf8-payload\n")

    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "core.quotePath", "true"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"], cwd=repo, check=True
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True)
    subprocess.run(["git", "tag", "client-v0.4.0"], cwd=repo, check=True)

    ok, files = sdk_gate._read_tagged_package_files(repo, "client-v0.4.0")
    assert ok is True
    assert files[Path("notes — utf8.txt")] == b"utf8-payload\n"
