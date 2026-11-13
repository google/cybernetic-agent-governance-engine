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

"""Enforce standalone ``cage-client`` wheel isolation and retirement of ``src/gateway/client/``.

Following ``client-v0.3.0`` and the advisor SDK refactor, ``packages/cage-client/``
is the sole source tree for ``cage-client`` and in-repo consumers depend on the
built release wheel (never on ``packages/cage-client/src/`` or a second copy).
This zero-waiver gate fails if:

1. the retired in-tree mirror ``src/gateway/client/`` reappears;
2. ``packages/cage-client/src/cage_client/`` is missing ``py.typed`` or drops
   below its module/import corpus floor;
3. any ``.py`` module in ``packages/cage-client/src/cage_client/`` imports
   ``src`` or ``proof`` (absolute monorepo imports break standalone installs);
4. ``pyproject.toml`` binds ``cage-client`` to a local source path instead of a
   built ``.whl`` URL in ``[tool.uv.sources]``; or
5. any Python module under ``src/`` or ``examples/`` imports ``src.gateway.client``.

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

import tomllib

REPO_ROOT = Path(__file__).resolve().parent.parent
RETIRED_MIRROR_REL = Path("src/gateway/client")
PACKAGE_REL = Path("packages/cage-client/src/cage_client")
PACKAGE_SRC = REPO_ROOT / PACKAGE_REL
ADVISOR_CLIENT_REL = Path(
    "src/governed_financial_advisor/infrastructure/gateway_client.py"
)

FORBIDDEN_ROOTS: frozenset[str] = frozenset({"src", "proof"})
MIN_EXPECTED_REPO_MODULES = 8
MIN_EXPECTED_REPO_IMPORTS = 10


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect_files(root: Path) -> dict[Path, Path]:
    """Return ``{relative_path: full_path}`` for every file under ``root`` except ``__pycache__``."""
    collected: dict[Path, Path] = {}
    for candidate in sorted(root.rglob("*")):
        if "__pycache__" in candidate.parts or not candidate.is_file():
            continue
        collected[candidate.relative_to(root)] = candidate
    return collected


def collect_py_files(root: Path) -> dict[Path, Path]:
    """Return ``{relative_path: full_path}`` for the ``.py`` modules under ``root``."""
    return {
        rel_path: full_path
        for rel_path, full_path in collect_files(root).items()
        if rel_path.suffix == ".py"
    }


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


def import_violations_with_stats(
    package_src: Path = PACKAGE_SRC,
    *,
    display_base: Path | None = None,
) -> tuple[list[str], int]:
    """Return ``(violations, recognized_import_count)`` for ``package_src``."""
    if not package_src.is_dir():
        return [f"{package_src} does not exist"], 0

    base = display_base if display_base is not None else package_src.parent
    errors: list[str] = []
    import_count = 0
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

        extracted = _extract_root_imports(tree)
        import_count += len(extracted)
        for lineno, mod_name in extracted:
            if mod_name.split(".")[0] in FORBIDDEN_ROOTS:
                errors.append(f"{disp}:{lineno}: imports {mod_name!r}")
    return errors, import_count


def import_violations(
    package_src: Path = PACKAGE_SRC,
    *,
    display_base: Path | None = None,
) -> list[str]:
    """Return violations for any ``.py`` module importing ``src`` or ``proof``."""
    errors, _ = import_violations_with_stats(package_src, display_base=display_base)
    return errors


def wheel_and_retirement_violations(repo_root: Path = REPO_ROOT) -> list[str]:
    """Verify mirror retirement, py.typed presence, wheel URL binding, and advisor SDK usage."""
    errors: list[str] = []
    retired_dir = repo_root / RETIRED_MIRROR_REL
    package_dir = repo_root / PACKAGE_REL

    # Bytecode left in __pycache__ by an earlier checkout is not importable
    # without its source, so only a real file brings the mirror back.
    mirror_files = (
        sorted(
            path.relative_to(repo_root).as_posix()
            for path in retired_dir.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
        )
        if retired_dir.is_dir()
        else []
    )
    if mirror_files:
        errors.append(
            f"{RETIRED_MIRROR_REL} exists (retired in-tree SDK mirror must stay removed; "
            f"depend on the built cage-client wheel instead): {', '.join(mirror_files[:5])}"
        )
    if not package_dir.is_dir():
        errors.append(f"{PACKAGE_REL} does not exist")
        return errors

    package_files = collect_files(package_dir)
    if not any(rel_path.suffix == ".py" for rel_path in package_files):
        errors.append(f"no .py modules found under {PACKAGE_REL}")
    if Path("py.typed") not in package_files:
        errors.append(
            f"{PACKAGE_REL / 'py.typed'} is missing (PEP 561 marker required)"
        )

    pyproject_path = repo_root / "pyproject.toml"
    if pyproject_path.is_file():
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        sources = data.get("tool", {}).get("uv", {}).get("sources", {})
        cage_source = sources.get("cage-client")
        wheel_url = (
            str(cage_source.get("url", "")) if isinstance(cage_source, dict) else ""
        )
        if not isinstance(cage_source, dict) or not wheel_url.endswith(".whl"):
            errors.append(
                "pyproject.toml [tool.uv.sources].cage-client must pin a built .whl URL "
                f"(got {cage_source!r})"
            )
        if isinstance(cage_source, dict) and "path" in cage_source:
            errors.append(
                "pyproject.toml [tool.uv.sources].cage-client must not use a local path source"
            )
        pkg_pyproject = repo_root / "packages" / "cage-client" / "pyproject.toml"
        if wheel_url.endswith(".whl") and pkg_pyproject.is_file():
            pkg_data = tomllib.loads(pkg_pyproject.read_text(encoding="utf-8"))
            pkg_version = str(pkg_data.get("project", {}).get("version", "")).strip()
            wheel_name = wheel_url.rsplit("/", 1)[-1]
            expected_prefix = f"cage_client-{pkg_version}-"
            if pkg_version and not wheel_name.startswith(expected_prefix):
                errors.append(
                    f"packages/cage-client/pyproject.toml version {pkg_version!r} "
                    f"does not match pinned wheel {wheel_name!r} in pyproject.toml"
                )

    for scan_rel in (Path("src"), Path("examples")):
        scan_dir = repo_root / scan_rel
        if not scan_dir.is_dir():
            continue
        for _, py_path in collect_py_files(scan_dir).items():
            disp = py_path.relative_to(repo_root)
            try:
                tree = ast.parse(
                    py_path.read_text(encoding="utf-8"), filename=str(py_path)
                )
            except (OSError, SyntaxError) as exc:
                errors.append(f"{disp}: failed to parse Python AST: {exc}")
                continue
            for lineno, mod_name in _extract_root_imports(tree):
                if mod_name == "src.gateway.client" or mod_name.startswith(
                    "src.gateway.client."
                ):
                    errors.append(
                        f"{disp}:{lineno}: imports retired mirror {mod_name!r} "
                        "(import 'cage_client' from the installed wheel instead)"
                    )

    advisor_client = repo_root / ADVISOR_CLIENT_REL
    if advisor_client.is_file():
        tree = ast.parse(
            advisor_client.read_text(encoding="utf-8"), filename=str(advisor_client)
        )
        root_mods = {
            mod_name.split(".")[0] for _, mod_name in _extract_root_imports(tree)
        }
        if "cage_client" not in root_mods:
            errors.append(
                f"{ADVISOR_CLIENT_REL} must import 'cage_client' so the advisor exercises the built SDK wheel"
            )

    return errors


def installed_wheel_parity_violations(
    package_dir: Path, installed_dir: Path | None
) -> list[str]:
    """Verify SHA-256 byte parity between ``packages/cage-client/src/cage_client`` and an installed wheel."""
    if installed_dir is None or not installed_dir.is_dir() or not package_dir.is_dir():
        return []
    src_files = collect_files(package_dir)
    wheel_files = collect_files(installed_dir)
    errors: list[str] = []
    for rel_path in sorted(set(src_files) | set(wheel_files)):
        if rel_path not in wheel_files:
            errors.append(
                f"{PACKAGE_REL / rel_path}: present in working tree but missing from installed cage-client wheel"
            )
            continue
        if rel_path not in src_files:
            errors.append(
                f"{rel_path}: present in installed cage-client wheel but missing from {PACKAGE_REL}"
            )
            continue
        src_sha = _sha256(src_files[rel_path])
        wheel_sha = _sha256(wheel_files[rel_path])
        if src_sha != wheel_sha:
            errors.append(
                f"{PACKAGE_REL / rel_path}: SHA-256 {src_sha[:12]} diverges from installed cage-client wheel {wheel_sha[:12]} "
                "(cut and pin a new release wheel whenever packages/cage-client changes)"
            )
    return errors


def _resolve_installed_wheel_dir() -> Path | None:
    import importlib.util

    spec = importlib.util.find_spec("cage_client")
    if spec is None or not spec.origin:
        return None
    origin_parent = Path(spec.origin).resolve().parent
    if "site-packages" not in origin_parent.as_posix():
        return None
    return origin_parent


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Zero-waiver gate enforcing src/gateway/client/ retirement, "
            "standalone packages/cage-client/ isolation, and built-wheel consumption."
        )
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Repository root directory (defaults to parent of scripts/).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print verified module list and SHA-256 digests.",
    )
    parser.add_argument(
        "--min-modules",
        type=int,
        default=None,
        help="Minimum Python modules expected in packages/cage-client/src/cage_client/.",
    )
    parser.add_argument(
        "--min-imports",
        type=int,
        default=None,
        help="Minimum top-level imports expected across packages/cage-client/src/cage_client/.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    repo_root = (args.repo_root if args.repo_root is not None else REPO_ROOT).resolve()
    is_live_repo = repo_root == REPO_ROOT.resolve()
    min_modules = (
        args.min_modules
        if args.min_modules is not None
        else (MIN_EXPECTED_REPO_MODULES if is_live_repo else 1)
    )
    min_imports = (
        args.min_imports
        if args.min_imports is not None
        else (MIN_EXPECTED_REPO_IMPORTS if is_live_repo else 1)
    )

    package_dir = repo_root / PACKAGE_REL
    pkg_import_errors, pkg_imports = import_violations_with_stats(
        package_dir, display_base=repo_root
    )
    wheel_parity_errors = (
        installed_wheel_parity_violations(package_dir, _resolve_installed_wheel_dir())
        if is_live_repo
        else []
    )
    errors = (
        wheel_and_retirement_violations(repo_root)
        + pkg_import_errors
        + wheel_parity_errors
    )

    if not errors and package_dir.is_dir():
        pkg_count = len(collect_py_files(package_dir))
        if pkg_count < min_modules:
            errors.append(
                f"vacuous/blind corpus floor failure: cage_client modules {pkg_count} < minimum expected {min_modules}"
            )
        if pkg_imports < min_imports:
            errors.append(
                f"vacuous/blind corpus floor failure: recognized root imports "
                f"(package={pkg_imports}) < minimum expected {min_imports}"
            )

    if args.verbose and package_dir.is_dir():
        package_files = collect_files(package_dir)
        print(
            f"Scanning standalone client SDK: {len(package_files)} file(s) in {PACKAGE_REL} "
            f"({pkg_imports} root imports)..."
        )
        for rel_path, full_path in sorted(package_files.items()):
            print(f"  ✓ {rel_path} (sha256:{_sha256(full_path)[:12]})")

    if errors:
        print(
            f"❌ cage-client standalone wheel gate failed with {len(errors)} violation(s):",
            file=sys.stderr,
        )
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    py_count = len(collect_py_files(package_dir))
    total_count = len(collect_files(package_dir))
    print(
        f"✅ cage-client standalone wheel gate: {total_count} files ({py_count} Python modules), "
        f"{pkg_imports} root imports verified, src/gateway/client/ retired, built .whl source pinned"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
