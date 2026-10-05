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

"""Static image-packaging contract for ``src/compliance_bridge/Dockerfile``.

Guards against packaging omissions such as ``8d2ccf03``, where
``EvidenceCustodian.from_env()`` ran at startup and lazy-imported
``src.integrations.storage_gcs.cold_store.GcsColdStore`` via
``src/gateway/governance/evidence/factory.py``, crashing with
``ModuleNotFoundError: No module named 'src.integrations'`` because
``src/integrations`` and ``src/__init__.py`` were not ``COPY``'d into the
compliance-bridge container image.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOCKERFILE = _REPO_ROOT / "src" / "compliance_bridge" / "Dockerfile"
_COMPLIANCE_BRIDGE_DIR = _REPO_ROOT / "src" / "compliance_bridge"
_EVIDENCE_FACTORY = (
    _REPO_ROOT / "src" / "gateway" / "governance" / "evidence" / "factory.py"
)
_SIGNER_FACTORY = _REPO_ROOT / "src" / "gateway" / "governance" / "signer_factory.py"

_COPY_INSTRUCTION = re.compile(r"^\s*COPY\s+(?:--\S+\s+)*(\S+)\s+(\S+)\s*$")


def _parse_dockerfile_copies(dockerfile_text: str) -> list[tuple[str, str]]:
    """Return ``(src, dest)`` pairs for non-``--from=`` ``COPY`` lines."""
    copies: list[tuple[str, str]] = []
    for raw_line in dockerfile_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "--from=" in line:
            continue
        match = _COPY_INSTRUCTION.match(line)
        if match:
            src_path = match.group(1).rstrip("/")
            dest_path = match.group(2).rstrip("/")
            copies.append((src_path, dest_path))
    return copies


def _resolve_module_files(module_name: str) -> list[Path]:
    parts = module_name.split(".")
    candidate = _REPO_ROOT.joinpath(*parts)
    out: list[Path] = []
    py_file = candidate.with_suffix(".py")
    if py_file.is_file():
        out.append(py_file)
    init_file = candidate / "__init__.py"
    if init_file.is_file():
        out.append(init_file)
    return out


def _collect_imported_src_packages() -> set[str]:
    """Return all top-level ``src.<pkg>`` packages imported directly or transitively
    by ``src/compliance_bridge/**``, ``evidence/factory.py``, or ``signer_factory.py``.
    """
    queue: list[Path] = [
        *sorted(_COMPLIANCE_BRIDGE_DIR.rglob("*.py")),
        _EVIDENCE_FACTORY,
        _SIGNER_FACTORY,
    ]
    visited: set[Path] = set()
    packages: set[str] = set()

    while queue:
        path = queue.pop()
        if path in visited or not path.is_file():
            continue
        visited.add(path)

        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel_parent_parts = list(path.relative_to(_REPO_ROOT).parent.parts)

        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = (
                        rel_parent_parts[: -(node.level - 1)]
                        if node.level > 1
                        else rel_parent_parts
                    )
                    rel_mod = ".".join(base + ([node.module] if node.module else []))
                    modules.append(rel_mod)
                    for alias in node.names:
                        modules.append(f"{rel_mod}.{alias.name}")
                elif node.module:
                    modules.append(node.module)
                    for alias in node.names:
                        modules.append(f"{node.module}.{alias.name}")

            for mod in modules:
                if mod.startswith("compliance_bridge"):
                    mod = f"src.{mod}"
                if mod.startswith("src."):
                    parts = mod.split(".")
                    if len(parts) >= 2 and parts[1] != "__init__":
                        pkg = parts[1]
                        if (_REPO_ROOT / "src" / pkg).is_dir():
                            packages.add(pkg)
                    for target in _resolve_module_files(mod):
                        queue.append(target)

    return packages


def _missing_dockerfile_src_packages(
    dockerfile_text: str, required_packages: set[str]
) -> set[str]:
    copies = set(_parse_dockerfile_copies(dockerfile_text))
    missing: set[str] = set()
    if ("src/__init__.py", "/app/src/__init__.py") not in copies:
        missing.add("__init__.py")
    for pkg in required_packages:
        if (f"src/{pkg}", f"/app/src/{pkg}") not in copies:
            missing.add(pkg)
    return missing


def test_compliance_bridge_dockerfile_copies_all_imported_src_packages() -> None:
    dockerfile_text = _DOCKERFILE.read_text(encoding="utf-8")
    required_packages = _collect_imported_src_packages()

    # Sanity-check that the static scan discovers all three known packages,
    # including lazy G3-allowlisted imports into src.integrations.
    assert {"compliance_bridge", "gateway", "integrations"} <= required_packages

    missing = _missing_dockerfile_src_packages(dockerfile_text, required_packages)
    assert missing == set(), (
        f"src/compliance_bridge/Dockerfile is missing COPY instructions for "
        f"imported src packages: {sorted(missing)}"
    )


def test_contract_check_fails_when_copied_package_is_missing() -> None:
    """Negative test: removing ``COPY src/integrations`` or ``src/__init__.py``
    is detected as a contract violation (reproducing ``8d2ccf03``).
    """
    dockerfile_text = _DOCKERFILE.read_text(encoding="utf-8")
    required_packages = _collect_imported_src_packages()

    broken_no_integrations = "\n".join(
        line for line in dockerfile_text.splitlines() if "src/integrations" not in line
    )
    assert _missing_dockerfile_src_packages(
        broken_no_integrations, required_packages
    ) == {"integrations"}

    broken_no_init = "\n".join(
        line for line in dockerfile_text.splitlines() if "src/__init__.py" not in line
    )
    assert _missing_dockerfile_src_packages(broken_no_init, required_packages) == {
        "__init__.py"
    }


def test_compliance_extra_includes_google_cloud_kms_for_evidence_signer() -> None:
    """``EvidenceCustodian.from_env()`` initializes ``GCPKMSProvider`` at startup,
    which requires ``google-cloud-kms``. Since ``src/compliance_bridge/Dockerfile``
    installs ``--extra compliance --extra langfuse``, the ``compliance`` extra in
    ``pyproject.toml`` must include ``google-cloud-kms``.
    """
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
        import tomli as tomllib  # type: ignore[no-redef]

    pyproject = tomllib.loads(
        (_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    compliance_deps: list[str] = pyproject["project"]["optional-dependencies"][
        "compliance"
    ]
    assert any(dep.startswith("google-cloud-kms") for dep in compliance_deps), (
        "pyproject.toml [project.optional-dependencies].compliance must include "
        f"google-cloud-kms for compliance-bridge KMS signing; got: {compliance_deps}"
    )
