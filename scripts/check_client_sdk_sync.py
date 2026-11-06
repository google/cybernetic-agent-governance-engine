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

"""Keep packages/cage-client a byte-identical, standalone copy of src/gateway/client/.

Both the in-tree mirror (``src/gateway/client/``) and the distributable wheel
source (``packages/cage-client/src/cage_client/``) ship the exact same Policy
Enforcement Point (PEP) client SDK. This zero-waiver gate fails if:

1. the set of ``.py`` modules under ``src/gateway/client/`` (excluding
   ``__pycache__``) does not match ``packages/cage-client/src/cage_client/``
   1-to-1 (missing or extra modules in either tree);
2. any paired ``.py`` module differs byte-for-byte (SHA-256);
3. any ``.py`` module in either client tree imports ``src`` or ``proof``
   (absolute monorepo imports would break standalone ``cage-client`` installs).

Zero waivers and zero allowlists are permitted.

Usage:
    uv run python scripts/check_client_sdk_sync.py --verbose
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import sys
from collections.abc import Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
KERNEL_REL = Path("src/gateway/client")
PACKAGE_REL = Path("packages/cage-client/src/cage_client")
KERNEL_SRC = REPO_ROOT / KERNEL_REL
PACKAGE_SRC = REPO_ROOT / PACKAGE_REL

FORBIDDEN_ROOTS: frozenset[str] = frozenset({"src", "proof"})


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect_py_files(root: Path) -> dict[Path, Path]:
    """Return ``{relative_path: full_path}`` for all ``.py`` files excluding ``__pycache__``."""
    collected: dict[Path, Path] = {}
    for candidate in sorted(root.rglob("*.py")):
        if "__pycache__" in candidate.parts or not candidate.is_file():
            continue
        collected[candidate.relative_to(root)] = candidate
    return collected


def sync_violations(repo_root: Path = REPO_ROOT) -> list[str]:
    """Return violations for missing, extra, or byte-divergent ``.py`` modules."""
    kernel_dir = repo_root / KERNEL_REL
    package_dir = repo_root / PACKAGE_REL
    errors: list[str] = []

    if not kernel_dir.is_dir():
        errors.append(f"{KERNEL_REL} does not exist")
    if not package_dir.is_dir():
        errors.append(f"{PACKAGE_REL} does not exist")
    if errors:
        return errors

    kernel_files = collect_py_files(kernel_dir)
    package_files = collect_py_files(package_dir)

    if not kernel_files:
        errors.append(f"no .py modules found under {KERNEL_REL}")
    if not package_files:
        errors.append(f"no .py modules found under {PACKAGE_REL}")
    if errors:
        return errors

    all_rel_paths = sorted(set(kernel_files) | set(package_files))
    for rel_path in all_rel_paths:
        in_kernel = rel_path in kernel_files
        in_package = rel_path in package_files
        if in_kernel and not in_package:
            errors.append(
                f"{PACKAGE_REL / rel_path} is missing (present at {KERNEL_REL / rel_path})"
            )
            continue
        if in_package and not in_kernel:
            errors.append(
                f"{KERNEL_REL / rel_path} is missing (extra module at {PACKAGE_REL / rel_path})"
            )
            continue
        kernel_sha = _sha256(kernel_files[rel_path])
        package_sha = _sha256(package_files[rel_path])
        if kernel_sha != package_sha:
            errors.append(
                f"{PACKAGE_REL / rel_path} differs from {KERNEL_REL / rel_path} "
                f"(sha256 {package_sha[:12]} != {kernel_sha[:12]})"
            )
    return errors


def _extract_root_imports(tree: ast.AST) -> list[tuple[int, str]]:
    """Return ``(lineno, module_name)`` for all absolute top-level root imports."""
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.append((node.lineno, node.module))
    return found


def import_violations(
    package_src: Path = PACKAGE_SRC,
    *,
    display_base: Path | None = None,
) -> list[str]:
    """Return violations for any ``.py`` module importing ``src`` or ``proof``."""
    if not package_src.is_dir():
        return [f"{package_src} does not exist"]

    base = display_base if display_base is not None else package_src.parent
    errors: list[str] = []
    for rel_path, full_path in collect_py_files(package_src).items():
        disp = (
            full_path.relative_to(base) if full_path.is_relative_to(base) else rel_path
        )
        try:
            source_text = full_path.read_text(encoding="utf-8")
            tree = ast.parse(source_text, filename=str(full_path))
        except (OSError, SyntaxError) as exc:
            errors.append(f"{disp}: failed to parse Python AST: {exc}")
            continue

        for lineno, mod_name in _extract_root_imports(tree):
            if mod_name.split(".")[0] in FORBIDDEN_ROOTS:
                errors.append(f"{disp}:{lineno}: imports {mod_name!r}")
    return errors


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Zero-waiver sync gate ensuring src/gateway/client/ and "
            "packages/cage-client/src/cage_client/ are 1-to-1 byte-identical "
            "and free of monorepo src/ or proof/ imports."
        )
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root directory (defaults to parent of scripts/).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print verified module list and SHA-256 digests.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    repo_root = args.repo_root.resolve()
    kernel_dir = repo_root / KERNEL_REL
    package_dir = repo_root / PACKAGE_REL

    errors = (
        sync_violations(repo_root)
        + import_violations(package_dir, display_base=repo_root)
        + import_violations(kernel_dir, display_base=repo_root)
    )

    if args.verbose and kernel_dir.is_dir() and package_dir.is_dir():
        kernel_files = collect_py_files(kernel_dir)
        package_files = collect_py_files(package_dir)
        print(
            f"Scanning client SDK trees: {len(kernel_files)} module(s) in {KERNEL_REL}, "
            f"{len(package_files)} module(s) in {PACKAGE_REL}..."
        )
        if not errors:
            for rel_path, full_path in kernel_files.items():
                print(f"  ✓ {rel_path} (sha256:{_sha256(full_path)[:12]})")

    if errors:
        for error in errors:
            print(f"❌ {error}", file=sys.stderr)
        return 1

    module_count = len(collect_py_files(kernel_dir))
    print(
        f"✅ cage-client sync: {module_count} Python modules byte-identical, "
        "no src/ or proof/ imports"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
