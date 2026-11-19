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

"""Enforce standalone ``cage-client`` wheel isolation, release-state honesty, and mirror retirement.

``packages/cage-client/`` is the sole source tree for ``cage-client``, and in-repo
consumers install it as a built non-editable wheel (never an editable source import
or a second in-tree copy). This zero-waiver gate fails if:

1. the retired in-tree mirror ``src/gateway/client/`` reappears;
2. ``packages/cage-client/src/cage_client/`` is missing ``py.typed`` or drops
   below its module/import corpus floor;
3. any ``.py`` module in ``packages/cage-client/src/cage_client/`` imports
   ``src`` or ``proof`` (absolute monorepo imports break standalone installs);
4. ``pyproject.toml`` binds ``cage-client`` to an editable path or invalid source
   rather than a built ``.whl`` URL or ``{ path = "packages/cage-client", editable = false }``,
   or its ``cage-client==<version>`` pins or ``__version__`` diverge from
   ``packages/cage-client/pyproject.toml``;
5. ``packages/cage-client/pyproject.toml`` ``[tool.cage.release].status`` violates
   the release-state contract:
     - ``"published"`` requires ``git`` tag ``client-v<version>`` to exist AND
       ``packages/cage-client/src/cage_client/`` to match that tag byte-for-byte;
     - ``"unreleased"`` requires ``client-v<version>`` NOT to exist yet AND
       ``<version>`` to be strictly greater than the latest ``client-v*`` tag;
     - any missing or unknown status fails closed;
6. the installed ``cage_client`` package in the active environment is loaded from
   outside ``site-packages`` (editable install) or diverges by SHA-256 from
   ``packages/cage-client/src/cage_client/``; or
7. any Python module under ``src/`` or ``examples/`` imports ``src.gateway.client``,
   or the advisor's ``GatewayClient`` stops importing ``cage_client``.

Usage:
    uv run python scripts/check_client_sdk_sync.py --verbose
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
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
VALID_RELEASE_STATUSES: frozenset[str] = frozenset({"published", "unreleased"})
_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_CLIENT_TAG_PREFIX = "client-v"
_GIT_TIMEOUT_SECONDS = 15
MIN_EXPECTED_REPO_MODULES = 8
MIN_EXPECTED_REPO_IMPORTS = 10


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_semver(version: str) -> tuple[int, int, int] | None:
    match = _SEMVER_RE.fullmatch(version.strip())
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def _git_bytes(repo_root: Path, *args: str) -> tuple[bool, bytes]:
    git = shutil.which("git")
    if git is None:
        return False, b"git is not installed"
    try:
        result = subprocess.run(
            [git, *args],
            cwd=repo_root,
            capture_output=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        return False, str(err).encode("utf-8")
    return result.returncode == 0, result.stdout


def _list_client_release_tags(repo_root: Path) -> tuple[bool, list[str]]:
    """Return ``(git_available, client_v_tags)`` from local git refs."""
    ok, raw = _git_bytes(repo_root, "tag", "-l", f"{_CLIENT_TAG_PREFIX}*")
    if not ok:
        return False, []
    tags = [
        line.strip()
        for line in raw.decode("utf-8", errors="replace").splitlines()
        if line.strip()
    ]
    return True, sorted(tags)


def _read_tagged_package_files(
    repo_root: Path, tag: str
) -> tuple[bool, dict[Path, bytes]]:
    """Read ``{relative_path: content_bytes}`` for ``PACKAGE_REL`` at ``tag``."""
    prefix = PACKAGE_REL.as_posix()
    ok, raw = _git_bytes(repo_root, "ls-tree", "-r", "--name-only", tag, "--", prefix)
    if not ok:
        return False, {}
    files: dict[Path, bytes] = {}
    for line in raw.decode("utf-8", errors="replace").splitlines():
        rel_repo = line.strip()
        if not rel_repo:
            continue
        rel_path = Path(rel_repo).relative_to(PACKAGE_REL)
        if "__pycache__" in rel_path.parts:
            continue
        show_ok, blob = _git_bytes(repo_root, "show", f"{tag}:{rel_repo}")
        if not show_ok:
            return False, {}
        files[rel_path] = blob
    return True, files


def _read_init_version(package_dir: Path) -> str | None:
    init_path = package_dir / "__init__.py"
    if not init_path.is_file():
        return None
    try:
        tree = ast.parse(init_path.read_text(encoding="utf-8"), filename=str(init_path))
    except (OSError, SyntaxError):
        return None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id == "__version__"
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    return node.value.value.strip()
    return None


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


def release_state_violations(
    repo_root: Path = REPO_ROOT,
    *,
    cutting_release_tag: str | None = None,
    git_tags: Sequence[str] | None = None,
    tagged_tree_files: Mapping[Path, bytes] | None = None,
) -> list[str]:
    """Verify ``packages/cage-client/pyproject.toml`` ``[tool.cage.release]`` honesty.

    Prevents declaring a version that has no corresponding release unless it is
    explicitly marked ``status = "unreleased"``, prevents leaving ``"unreleased"``
    after its ``client-v<version>`` tag exists, and prevents editing ``packages/cage-client``
    after a release without bumping the version and switching to ``"unreleased"``.
    """
    pkg_pyproject = repo_root / "packages" / "cage-client" / "pyproject.toml"
    if not pkg_pyproject.is_file():
        return [f"{pkg_pyproject.relative_to(repo_root)} does not exist"]

    pkg_data = tomllib.loads(pkg_pyproject.read_text(encoding="utf-8"))
    pkg_version = str(pkg_data.get("project", {}).get("version", "")).strip()
    pkg_semver = _parse_semver(pkg_version)
    if pkg_semver is None:
        return [
            f"packages/cage-client/pyproject.toml project.version {pkg_version!r} "
            "must be a strict MAJOR.MINOR.PATCH semantic version"
        ]

    release_cfg = pkg_data.get("tool", {}).get("cage", {}).get("release", {})
    status = (
        str(release_cfg.get("status", "")).strip()
        if isinstance(release_cfg, dict)
        else ""
    )
    if status not in VALID_RELEASE_STATUSES:
        return [
            "packages/cage-client/pyproject.toml [tool.cage.release].status must be "
            f"one of {sorted(VALID_RELEASE_STATUSES)!r} (got {status!r})"
        ]

    expected_tag = f"{_CLIENT_TAG_PREFIX}{pkg_version}"
    if git_tags is not None:
        tags = list(git_tags)
    else:
        git_ok, tags = _list_client_release_tags(repo_root)
        if not git_ok:
            return [
                "Unable to query git client-v* tags to verify [tool.cage.release].status "
                f"({status!r} for version {pkg_version!r})"
            ]

    tag_semvers: list[tuple[tuple[int, int, int], str]] = []
    for tag in tags:
        if tag.startswith(_CLIENT_TAG_PREFIX):
            parsed = _parse_semver(tag.removeprefix(_CLIENT_TAG_PREFIX))
            if parsed is not None:
                tag_semvers.append((parsed, tag))

    if cutting_release_tag is not None:
        if cutting_release_tag != expected_tag:
            return [
                f"--cutting-release-tag {cutting_release_tag!r} does not match "
                f"expected tag {expected_tag!r} from packages/cage-client/pyproject.toml"
            ]
        other_semvers = [sv for sv, t in tag_semvers if t != expected_tag]
        if status == "unreleased":
            if other_semvers and pkg_semver <= max(other_semvers):
                highest_ver = ".".join(str(p) for p in max(other_semvers))
                return [
                    f"Cannot cut unreleased cage-client {pkg_version!r}: version must be "
                    f"strictly greater than existing release {highest_ver!r}"
                ]
            return []
        # status == "published" on an existing tag falls through to full tag+tree check

    errors: list[str] = []
    if status == "published":
        if expected_tag not in tags:
            errors.append(
                f"packages/cage-client/pyproject.toml declares version {pkg_version!r} as "
                f"status='published', but git tag {expected_tag!r} does not exist "
                "(set status='unreleased' until the release tag is cut)"
            )
            return errors

        package_dir = repo_root / PACKAGE_REL
        if tagged_tree_files is not None:
            tag_files = dict(tagged_tree_files)
        else:
            ok_tree, tag_files = _read_tagged_package_files(repo_root, expected_tag)
            if not ok_tree:
                return [
                    f"Failed to read {PACKAGE_REL} tree from git tag {expected_tag!r}"
                ]

        src_files = collect_files(package_dir)
        for rel_path in sorted(set(src_files) | set(tag_files)):
            if rel_path not in tag_files:
                errors.append(
                    f"{PACKAGE_REL / rel_path}: added since published tag {expected_tag!r} "
                    "(bump version and set [tool.cage.release].status = 'unreleased')"
                )
                continue
            if rel_path not in src_files:
                errors.append(
                    f"{PACKAGE_REL / rel_path}: removed since published tag {expected_tag!r} "
                    "(bump version and set [tool.cage.release].status = 'unreleased')"
                )
                continue
            src_sha = _sha256(src_files[rel_path])
            tag_sha = _sha256_bytes(tag_files[rel_path])
            if src_sha != tag_sha:
                errors.append(
                    f"{PACKAGE_REL / rel_path}: SHA-256 {src_sha[:12]} diverges from "
                    f"published tag {expected_tag!r} ({tag_sha[:12]}) "
                    "(bump version and set [tool.cage.release].status = 'unreleased')"
                )
        return errors

    # status == "unreleased"
    if expected_tag in tags:
        errors.append(
            f"packages/cage-client/pyproject.toml still marks version {pkg_version!r} as "
            f"status='unreleased', but git tag {expected_tag!r} already exists "
            "(update [tool.cage.release].status = 'published')"
        )
    if tag_semvers:
        highest_semver, highest_tag = max(tag_semvers)
        if pkg_semver <= highest_semver:
            errors.append(
                f"Unreleased cage-client version {pkg_version!r} must be strictly greater "
                f"than latest published tag {highest_tag!r}"
            )
    return errors


def wheel_and_retirement_violations(repo_root: Path = REPO_ROOT) -> list[str]:
    """Verify mirror retirement, py.typed presence, non-editable wheel config, and advisor SDK usage."""
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

    pkg_pyproject = repo_root / "packages" / "cage-client" / "pyproject.toml"
    pkg_version = ""
    if pkg_pyproject.is_file():
        pkg_data = tomllib.loads(pkg_pyproject.read_text(encoding="utf-8"))
        pkg_version = str(pkg_data.get("project", {}).get("version", "")).strip()
        init_version = _read_init_version(package_dir)
        if init_version is not None and pkg_version and init_version != pkg_version:
            errors.append(
                f"{PACKAGE_REL / '__init__.py'} __version__={init_version!r} does not match "
                f"packages/cage-client/pyproject.toml version {pkg_version!r}"
            )

    pyproject_path = repo_root / "pyproject.toml"
    if pyproject_path.is_file():
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        sources = data.get("tool", {}).get("uv", {}).get("sources", {})
        cage_source = sources.get("cage-client")
        if not isinstance(cage_source, dict):
            errors.append(
                "pyproject.toml [tool.uv.sources].cage-client must pin a built .whl URL "
                "or { path = 'packages/cage-client', editable = false } "
                f"(got {cage_source!r})"
            )
        else:
            wheel_url = str(cage_source.get("url", ""))
            source_path = cage_source.get("path")
            if source_path is not None:
                norm_path = str(source_path).rstrip("/")
                if norm_path != "packages/cage-client":
                    errors.append(
                        "pyproject.toml [tool.uv.sources].cage-client path must be "
                        f"'packages/cage-client' (got {source_path!r})"
                    )
                if cage_source.get("editable") is not False:
                    errors.append(
                        "pyproject.toml [tool.uv.sources].cage-client path source must set "
                        "editable = false so uv builds and installs a standalone wheel"
                    )
            elif wheel_url.endswith(".whl"):
                wheel_name = wheel_url.rsplit("/", 1)[-1]
                expected_prefix = f"cage_client-{pkg_version}-"
                if pkg_version and not wheel_name.startswith(expected_prefix):
                    errors.append(
                        f"packages/cage-client/pyproject.toml version {pkg_version!r} "
                        f"does not match pinned wheel {wheel_name!r} in pyproject.toml"
                    )
            else:
                errors.append(
                    "pyproject.toml [tool.uv.sources].cage-client must pin a built .whl URL "
                    "or { path = 'packages/cage-client', editable = false } "
                    f"(got {cage_source!r})"
                )

        if pkg_version:
            dep_lists: list[tuple[str, list[object]]] = []
            test_group = data.get("dependency-groups", {}).get("test", [])
            if isinstance(test_group, list):
                dep_lists.append(("dependency-groups.test", test_group))
            advisor_extra = (
                data.get("project", {})
                .get("optional-dependencies", {})
                .get("advisor", [])
            )
            if isinstance(advisor_extra, list):
                dep_lists.append(
                    ("project.optional-dependencies.advisor", advisor_extra)
                )
            for section_name, deps in dep_lists:
                for entry in deps:
                    if isinstance(entry, str) and entry.startswith("cage-client=="):
                        pinned = entry.removeprefix("cage-client==").strip()
                        if pinned != pkg_version:
                            errors.append(
                                f"pyproject.toml [{section_name}] pins cage-client=={pinned}, "
                                f"but packages/cage-client/pyproject.toml declares {pkg_version!r}"
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
                "(rebuild/reinstall the non-editable cage-client wheel via `uv sync --reinstall-package cage-client`)"
            )
    return errors


def _resolve_installed_wheel_dir() -> tuple[Path | None, list[str]]:
    import importlib.util

    spec = importlib.util.find_spec("cage_client")
    if spec is None or not spec.origin:
        return None, []
    origin_parent = Path(spec.origin).resolve().parent
    if "site-packages" not in origin_parent.as_posix():
        return None, [
            f"installed cage_client resolves to {origin_parent} outside site-packages "
            "(editable/source-tree installs are forbidden; install the built wheel)"
        ]
    return origin_parent, []


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Zero-waiver gate enforcing src/gateway/client/ retirement, "
            "standalone packages/cage-client/ isolation, release-state honesty, "
            "and built-wheel consumption."
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
        "--cutting-release-tag",
        type=str,
        default=None,
        help="Release tag being cut in publish-client-sdk.yml (e.g. client-v0.4.0).",
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
    wheel_parity_errors: list[str] = []
    if is_live_repo:
        installed_dir, resolve_errors = _resolve_installed_wheel_dir()
        wheel_parity_errors.extend(resolve_errors)
        wheel_parity_errors.extend(
            installed_wheel_parity_violations(package_dir, installed_dir)
        )
    release_errors = (
        release_state_violations(
            repo_root, cutting_release_tag=args.cutting_release_tag
        )
        if is_live_repo
        else []
    )
    errors = (
        wheel_and_retirement_violations(repo_root)
        + pkg_import_errors
        + release_errors
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
        f"{pkg_imports} root imports verified, release-state contract satisfied, "
        f"src/gateway/client/ retired, non-editable wheel verified"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
