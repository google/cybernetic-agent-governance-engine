#!/usr/bin/env python3
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

"""Verify single-source-of-truth parity and zero-src/ isolation for cage-conformance.

Enforces:
1. Byte-for-byte SHA-256 equality between ``proof/model.py`` and
   ``packages/cage-conformance/src/cage_conformance/model.py``.
2. Byte-for-byte SHA-256 equality between ``proof/trace_conformance.py`` and
   ``packages/cage-conformance/src/cage_conformance/trace_conformance.py``.
3. AST import isolation: no module in ``packages/cage-conformance/`` may import
   from ``src`` or ``src.*``.

Usage:
    uv run python scripts/check_conformance_sync.py
"""

from __future__ import annotations

import ast
import hashlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PKG_SRC = REPO_ROOT / "packages" / "cage-conformance" / "src" / "cage_conformance"

SYNC_PAIRS: tuple[tuple[Path, Path], ...] = (
    (REPO_ROOT / "proof" / "model.py", PKG_SRC / "model.py"),
    (
        REPO_ROOT / "proof" / "trace_conformance.py",
        PKG_SRC / "trace_conformance.py",
    ),
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_sync_and_isolation() -> list[str]:
    """Return a list of violations (empty if conformant)."""
    errors: list[str] = []

    for authoritative, packaged in SYNC_PAIRS:
        if not authoritative.is_file():
            errors.append(f"Missing authoritative file: {authoritative}")
            continue
        if not packaged.is_file():
            errors.append(f"Missing packaged file: {packaged}")
            continue
        auth_hash = _sha256(authoritative)
        pkg_hash = _sha256(packaged)
        if auth_hash != pkg_hash:
            errors.append(
                f"SHA-256 mismatch between {authoritative.relative_to(REPO_ROOT)} "
                f"({auth_hash[:12]}) and {packaged.relative_to(REPO_ROOT)} ({pkg_hash[:12]}). "
                f"Copy from proof/ to packages/cage-conformance/src/cage_conformance/."
            )

    if not PKG_SRC.is_dir():
        errors.append(f"Missing package directory: {PKG_SRC}")
        return errors

    for py_file in sorted(PKG_SRC.rglob("*.py")):
        rel = py_file.relative_to(REPO_ROOT)
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(rel))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "src" or alias.name.startswith("src."):
                        errors.append(
                            f"{rel}:{node.lineno}: forbidden import '{alias.name}' "
                            "(cage-conformance must have zero src/ dependency)"
                        )
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module == "src" or node.module.startswith("src."):
                    errors.append(
                        f"{rel}:{node.lineno}: forbidden from-import '{node.module}' "
                        "(cage-conformance must have zero src/ dependency)"
                    )

    return errors


def main() -> int:
    errors = check_sync_and_isolation()
    if errors:
        for err in errors:
            print(f"❌ {err}", file=sys.stderr)
        return 1
    print(
        "✅ cage-conformance parity & zero-src/ isolation verified "
        f"({len(SYNC_PAIRS)} synced proof modules)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
