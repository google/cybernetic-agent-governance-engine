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

"""Unit tests for the zero-waiver client SDK parity gate (check_client_sdk_sync.py)."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_client_sdk_sync import (
    KERNEL_REL,
    KERNEL_SRC,
    PACKAGE_REL,
    PACKAGE_SRC,
    REPO_ROOT,
    import_violations,
    main,
    sync_violations,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


def _seed_synced_repo(tmp_path: Path) -> tuple[Path, Path]:
    """Create minimal byte-identical kernel and standalone client trees."""
    kernel_dir = tmp_path / KERNEL_REL
    package_dir = tmp_path / PACKAGE_REL
    for base in (kernel_dir, package_dir):
        (base / "adapters").mkdir(parents=True, exist_ok=True)
        (base / "__init__.py").write_text(
            '"""Client package."""\nfrom .core import CageClient\n',
            encoding="utf-8",
        )
        (base / "core.py").write_text(
            "import json\nimport httpx\n\nclass CageClient:\n    pass\n",
            encoding="utf-8",
        )
        (base / "adapters" / "__init__.py").write_text("", encoding="utf-8")
        (base / "adapters" / "langgraph.py").write_text(
            "from ..core import CageClient\n",
            encoding="utf-8",
        )
    return kernel_dir, package_dir


def test_real_repository_client_sdk_trees_are_in_sync() -> None:
    """Real repository src/gateway/client/ and packages/cage-client/ must pass with 0 waivers."""
    assert sync_violations(REPO_ROOT) == []
    assert import_violations(PACKAGE_SRC, display_base=REPO_ROOT) == []
    assert import_violations(KERNEL_SRC, display_base=REPO_ROOT) == []
    assert main(["--repo-root", str(REPO_ROOT), "--verbose"]) == 0


def test_identical_temp_trees_pass_and_ignore_pycache(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Identical .py sets pass even when __pycache__ artifacts exist on one side."""
    kernel_dir, _ = _seed_synced_repo(tmp_path)
    pycache_dir = kernel_dir / "__pycache__"
    pycache_dir.mkdir()
    (pycache_dir / "core.cpython-312.pyc").write_bytes(b"\x00\x01\x02")
    (pycache_dir / "stale_helper.py").write_text("x = 1\n", encoding="utf-8")

    assert sync_violations(tmp_path) == []
    assert main(["--repo-root", str(tmp_path), "--verbose"]) == 0
    captured = capsys.readouterr()
    assert "4 Python modules byte-identical" in captured.out
    assert "✓ core.py" in captured.out


def test_byte_divergent_module_fails_with_sha256_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Any byte divergence between paired modules fails with SHA-256 diagnostics."""
    _, package_dir = _seed_synced_repo(tmp_path)
    (package_dir / "core.py").write_text(
        "import json\nimport httpx\n\nclass CageClient:\n    DRIFT = True\n",
        encoding="utf-8",
    )

    errors = sync_violations(tmp_path)
    assert len(errors) == 1
    assert (
        "packages/cage-client/src/cage_client/core.py differs from src/gateway/client/core.py"
        in errors[0]
    )
    assert "sha256" in errors[0]

    assert main(["--repo-root", str(tmp_path)]) == 1
    assert "differs from" in capsys.readouterr().err


def test_missing_and_extra_modules_fail(tmp_path: Path) -> None:
    """Modules present in only one tree are reported symmetrically."""
    kernel_dir, package_dir = _seed_synced_repo(tmp_path)
    (kernel_dir / "new_kernel_only.py").write_text("X = 1\n", encoding="utf-8")
    (package_dir / "orphan_pkg_only.py").write_text("Y = 2\n", encoding="utf-8")

    errors = sync_violations(tmp_path)
    assert len(errors) == 2
    assert any(
        "packages/cage-client/src/cage_client/new_kernel_only.py is missing" in err
        for err in errors
    )
    assert any(
        "src/gateway/client/orphan_pkg_only.py is missing (extra module" in err
        for err in errors
    )


def test_missing_or_empty_directories_fail_closed(tmp_path: Path) -> None:
    """Missing or empty client directories never pass vacuously."""
    missing_errors = sync_violations(tmp_path)
    assert len(missing_errors) == 2
    assert main(["--repo-root", str(tmp_path)]) == 1

    (tmp_path / KERNEL_REL).mkdir(parents=True)
    (tmp_path / PACKAGE_REL).mkdir(parents=True)
    empty_errors = sync_violations(tmp_path)
    assert len(empty_errors) == 2
    assert any("no .py modules found" in err for err in empty_errors)


def test_forbidden_monorepo_imports_detected_while_relative_imports_allowed(
    tmp_path: Path,
) -> None:
    """Absolute imports from 'src' or 'proof' fail; relative and third-party imports pass."""
    kernel_dir, package_dir = _seed_synced_repo(tmp_path)
    bad_code = (
        "import httpx\n"
        "import src.gateway.governance\n"
        "from src.gateway.client.envelope import GovernanceEnvelope\n"
        "from proof.model import TIER_LABELS\n"
        "from .core import CageClient\n"
    )
    (kernel_dir / "bad_imports.py").write_text(bad_code, encoding="utf-8")
    (package_dir / "bad_imports.py").write_text(bad_code, encoding="utf-8")

    pkg_errors = import_violations(package_dir, display_base=tmp_path)
    assert len(pkg_errors) == 3
    assert any("imports 'src.gateway.governance'" in err for err in pkg_errors)
    assert any("imports 'src.gateway.client.envelope'" in err for err in pkg_errors)
    assert any("imports 'proof.model'" in err for err in pkg_errors)
    assert main(["--repo-root", str(tmp_path)]) == 1


def test_syntax_error_in_client_module_fails_closed(tmp_path: Path) -> None:
    """Unparseable Python source fails import_violations closed instead of crashing."""
    _, package_dir = _seed_synced_repo(tmp_path)
    (package_dir / "broken.py").write_text("def broken(:\n", encoding="utf-8")

    errors = import_violations(package_dir, display_base=tmp_path)
    assert len(errors) == 1
    assert "failed to parse Python AST" in errors[0]
