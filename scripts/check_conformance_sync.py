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

"""Keep packages/cage-conformance a byte-identical, standalone copy of proof/.

The standalone verifier must apply exactly the checks CAGE's own suite applies,
so it never forks the formal model or the checkers
(``docs/architecture/CONFORMANCE_VERIFIER_SPEC.md`` §2.2). This gate fails if:

1. a module in ``SYNC_PAIRS`` differs, byte for byte, from its ``proof/``
   original;
2. any package module imports ``src`` or ``proof`` (absolute ``proof`` imports
   would only resolve inside a CAGE checkout);
3. ``[tool.cage.release].status`` in the package's ``pyproject.toml`` disagrees
   with the ``conformance-v*`` git tags: ``"published"`` needs tag
   ``conformance-v<version>`` and a package tree byte-identical to that tag;
   ``"unreleased"`` needs no such tag yet and a version strictly newer than
   the latest ``conformance-v*`` tag.

Fix a sync failure by copying from ``proof/`` into the package, never the other
way round.

Usage:
    uv run python scripts/check_conformance_sync.py
    uv run python scripts/check_conformance_sync.py --cutting-release-tag conformance-v<version>
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import tomllib

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = REPO_ROOT / "packages" / "cage-conformance"
PACKAGE_SRC = PACKAGE_ROOT / "src" / "cage_conformance"

#: proof/ module -> its packaged copy (relative to the repository root).
SYNC_PAIRS: tuple[tuple[str, str], ...] = tuple(
    (f"proof/{name}", f"packages/cage-conformance/src/cage_conformance/{name}")
    for name in ("model.py", "trace_conformance.py", "stream_invariants.py")
)

FORBIDDEN_ROOTS = frozenset({"src", "proof"})
_RULE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]+$")
MIN_TRACE_RULES = 7
MIN_STREAM_RULES = 20

#: The tree a published ``conformance-v<version>`` tag must match byte for byte.
PACKAGE_REL = Path("packages/cage-conformance/src/cage_conformance")
VALID_RELEASE_STATUSES: frozenset[str] = frozenset({"published", "unreleased"})
CONFORMANCE_TAG_PREFIX = "conformance-v"
_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_GIT_TIMEOUT_SECONDS = 15


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assigned_value(tree: ast.Module, name: str) -> ast.expr | None:
    """Return the top-level AST value assigned to ``name``."""
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return node.value
        elif isinstance(node, ast.AnnAssign):
            if (
                isinstance(node.target, ast.Name)
                and node.target.id == name
                and node.value is not None
            ):
                return node.value
    return None


def _unwrap_mapping_proxy(expr: ast.expr) -> ast.expr:
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Name)
        and expr.func.id == "MappingProxyType"
        and expr.args
    ):
        return expr.args[0]
    return expr


def _string_dict_items(expr: ast.expr | None) -> dict[str, str] | None:
    if expr is None:
        return None
    unwrapped = _unwrap_mapping_proxy(expr)
    if not isinstance(unwrapped, ast.Dict):
        return None
    items: dict[str, str] = {}
    for key_node, val_node in zip(unwrapped.keys, unwrapped.values, strict=True):
        if (
            isinstance(key_node, ast.Constant)
            and isinstance(key_node.value, str)
            and isinstance(val_node, ast.Constant)
            and isinstance(val_node.value, str)
        ):
            items[key_node.value] = val_node.value
    return items


def _string_tuple_items(expr: ast.expr | None) -> tuple[str, ...] | None:
    if expr is None or not isinstance(expr, (ast.Tuple, ast.List)):
        return None
    out: list[str] = []
    for elt in expr.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            out.append(elt.value)
        else:
            return None
    return tuple(out)


def extract_emitted_proof_rules(proof_path: Path) -> set[str]:
    """Extract every Finding rule identifier emitted by a ``proof/`` checker module."""
    tree = ast.parse(proof_path.read_text(encoding="utf-8"), filename=str(proof_path))
    rules: set[str] = set()

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "Finding"
        ):
            rule_node: ast.expr | None = None
            if len(node.args) >= 2:
                rule_node = node.args[1]
            else:
                for kw in node.keywords:
                    if kw.arg == "rule":
                        rule_node = kw.value
                        break
            if isinstance(rule_node, ast.Constant) and isinstance(rule_node.value, str):
                rules.add(rule_node.value)

    for func in tree.body:
        if not isinstance(func, ast.FunctionDef) or func.returns is None:
            continue
        if "tuple[str, str]" not in ast.unparse(func.returns):
            continue
        for inner in ast.walk(func):
            if (
                isinstance(inner, ast.Tuple)
                and len(inner.elts) == 2
                and isinstance(inner.elts[0], ast.Constant)
                and isinstance(inner.elts[0].value, str)
                and _RULE_NAME_RE.fullmatch(inner.elts[0].value)
            ):
                rules.add(inner.elts[0].value)

    return rules


def sync_violations(repo_root: Path = REPO_ROOT) -> list[str]:
    """Each ``SYNC_PAIRS`` entry that is missing or differs from ``proof/``."""
    errors: list[str] = []
    for original, copy in SYNC_PAIRS:
        source, packaged = repo_root / original, repo_root / copy
        if not source.is_file() or not packaged.is_file():
            missing = original if not source.is_file() else copy
            errors.append(f"{missing} does not exist")
            continue
        if _sha256(source) != _sha256(packaged):
            errors.append(f"{copy} differs from {original}: copy it from proof/")
    return errors


def import_violations(package_src: Path = PACKAGE_SRC) -> list[str]:
    """Each import of ``src`` or ``proof`` in the package."""
    if not package_src.is_dir():
        return [f"{package_src} does not exist"]
    errors: list[str] = []
    for path in sorted(package_src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                if name.split(".")[0] in FORBIDDEN_ROOTS:
                    errors.append(
                        f"{path.relative_to(package_src.parent)}:{node.lineno}: "
                        f"imports {name!r}"
                    )
    return errors


def rule_coverage_violations(repo_root: Path = REPO_ROOT) -> list[str]:
    """Ensure ``runner.py`` ``TRACE_RULES`` and ``STREAM_RULES`` match ``proof/`` 1-to-1."""
    errors: list[str] = []
    pkg_src = repo_root / "packages" / "cage-conformance" / "src" / "cage_conformance"
    runner_path = pkg_src / "runner.py"
    trace_proof = repo_root / "proof" / "trace_conformance.py"
    stream_proof = repo_root / "proof" / "stream_invariants.py"

    for required in (runner_path, trace_proof, stream_proof):
        if not required.is_file():
            errors.append(f"{required.relative_to(repo_root)} does not exist")
    if errors:
        return errors

    runner_tree = ast.parse(
        runner_path.read_text(encoding="utf-8"), filename=str(runner_path)
    )
    trace_rules_map = _string_dict_items(_assigned_value(runner_tree, "TRACE_RULES"))
    stream_rules_map = _string_dict_items(_assigned_value(runner_tree, "STREAM_RULES"))
    if trace_rules_map is None:
        errors.append("runner.py is missing literal dict TRACE_RULES")
    if stream_rules_map is None:
        errors.append("runner.py is missing literal dict STREAM_RULES")
    if errors or trace_rules_map is None or stream_rules_map is None:
        return errors

    emitted_trace = extract_emitted_proof_rules(trace_proof)
    emitted_stream = extract_emitted_proof_rules(stream_proof)

    if len(emitted_trace) < MIN_TRACE_RULES:
        errors.append(
            f"proof/trace_conformance.py extracted {len(emitted_trace)} rule(s), "
            f"expected at least {MIN_TRACE_RULES}"
        )
    if len(emitted_stream) < MIN_STREAM_RULES:
        errors.append(
            f"proof/stream_invariants.py extracted {len(emitted_stream)} rule(s), "
            f"expected at least {MIN_STREAM_RULES}"
        )

    missing_trace = sorted(emitted_trace - set(trace_rules_map))
    stale_trace = sorted(set(trace_rules_map) - emitted_trace)
    if missing_trace:
        errors.append(
            f"runner.py TRACE_RULES is missing rule(s) emitted by proof/trace_conformance.py: {missing_trace}"
        )
    if stale_trace:
        errors.append(
            f"runner.py TRACE_RULES declares rule(s) not emitted by proof/trace_conformance.py: {stale_trace}"
        )

    missing_stream = sorted(emitted_stream - set(stream_rules_map))
    stale_stream = sorted(set(stream_rules_map) - emitted_stream)
    if missing_stream:
        errors.append(
            f"runner.py STREAM_RULES is missing rule(s) emitted by proof/stream_invariants.py: {missing_stream}"
        )
    if stale_stream:
        errors.append(
            f"runner.py STREAM_RULES declares rule(s) not emitted by proof/stream_invariants.py: {stale_stream}"
        )

    return errors


def internal_contract_violations(repo_root: Path = REPO_ROOT) -> list[str]:
    """Verify package metadata version, ``parties.json`` profiles, and endpoint vector files."""
    errors: list[str] = []
    pkg_root = repo_root / "packages" / "cage-conformance"
    pkg_src = pkg_root / "src" / "cage_conformance"
    pyproject_path = pkg_root / "pyproject.toml"
    init_path = pkg_src / "__init__.py"
    report_path = pkg_src / "report.py"
    runner_path = pkg_src / "runner.py"
    parties_path = pkg_src / "parties.json"

    for required in (
        pyproject_path,
        init_path,
        report_path,
        runner_path,
        parties_path,
    ):
        if not required.is_file():
            errors.append(f"{required.relative_to(repo_root)} does not exist")
    if errors:
        return errors

    pkg_data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    pyproject_version = str(pkg_data.get("project", {}).get("version", "")).strip()
    init_tree = ast.parse(
        init_path.read_text(encoding="utf-8"), filename=str(init_path)
    )
    init_ver_expr = _assigned_value(init_tree, "__version__")
    init_version = (
        init_ver_expr.value.strip()
        if isinstance(init_ver_expr, ast.Constant)
        and isinstance(init_ver_expr.value, str)
        else ""
    )
    if not pyproject_version or pyproject_version != init_version:
        errors.append(
            f"packages/cage-conformance/pyproject.toml version {pyproject_version!r} "
            f"!= __init__.py __version__ {init_version!r}"
        )

    report_tree = ast.parse(
        report_path.read_text(encoding="utf-8"), filename=str(report_path)
    )
    mode_profiles = _string_dict_items(_assigned_value(report_tree, "MODE_PROFILES"))
    endpoint_profiles = _string_tuple_items(
        _assigned_value(report_tree, "ENDPOINT_PROFILES")
    )
    if mode_profiles is None or endpoint_profiles is None:
        errors.append(
            "report.py must define literal MODE_PROFILES and ENDPOINT_PROFILES"
        )
        return errors

    expected_profiles = set(mode_profiles.values()) | set(endpoint_profiles)
    try:
        parties_doc = json.loads(parties_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"parties.json is invalid JSON: {exc}")
        return errors

    pinned_profiles = (
        set(parties_doc.get("profiles", {}))
        if isinstance(parties_doc, dict)
        and isinstance(parties_doc.get("profiles"), dict)
        else set()
    )
    missing_party_profiles = sorted(expected_profiles - pinned_profiles)
    if missing_party_profiles:
        errors.append(
            f"parties.json is missing profile pin(s): {missing_party_profiles}"
        )

    runner_tree = ast.parse(
        runner_path.read_text(encoding="utf-8"), filename=str(runner_path)
    )
    vector_map = _string_dict_items(
        _assigned_value(runner_tree, "_PROFILE_VECTOR_FILES")
    )
    if vector_map is None:
        errors.append("runner.py must define literal _PROFILE_VECTOR_FILES")
        return errors

    if set(vector_map) != set(endpoint_profiles):
        errors.append(
            f"runner.py _PROFILE_VECTOR_FILES keys {sorted(vector_map)} != "
            f"report.py ENDPOINT_PROFILES {sorted(endpoint_profiles)}"
        )

    vectors_dir = pkg_src / "vectors"
    for profile, filename in sorted(vector_map.items()):
        vec_file = vectors_dir / filename
        if not vec_file.is_file():
            errors.append(
                f"endpoint profile {profile!r} vector file {vec_file.relative_to(repo_root)} does not exist"
            )
            continue
        try:
            json.loads(vec_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(
                f"endpoint profile {profile!r} vector file {vec_file.relative_to(repo_root)} is invalid JSON: {exc}"
            )

    return errors


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


def _list_conformance_release_tags(repo_root: Path) -> tuple[bool, list[str]]:
    """Return ``(git_available, conformance_v_tags)`` from local git refs."""
    ok, raw = _git_bytes(repo_root, "tag", "-l", f"{CONFORMANCE_TAG_PREFIX}*")
    if not ok:
        return False, []
    tags = [
        line.strip()
        for line in raw.decode("utf-8", errors="replace").splitlines()
        if line.strip()
    ]
    return True, sorted(tags)


def collect_package_files(root: Path) -> dict[Path, Path]:
    """Return ``{relative_path: full_path}`` for every file under ``root`` except ``__pycache__``."""
    collected: dict[Path, Path] = {}
    for candidate in sorted(root.rglob("*")):
        if "__pycache__" in candidate.parts or not candidate.is_file():
            continue
        collected[candidate.relative_to(root)] = candidate
    return collected


def _read_tagged_package_files(
    repo_root: Path, tag: str
) -> tuple[bool, dict[Path, bytes]]:
    """Read ``{relative_path: content_bytes}`` for ``PACKAGE_REL`` at ``tag``."""
    ok, raw = _git_bytes(
        repo_root,
        "ls-tree",
        "-r",
        "-z",
        "--name-only",
        tag,
        "--",
        PACKAGE_REL.as_posix(),
    )
    if not ok:
        return False, {}
    files: dict[Path, bytes] = {}
    for entry in raw.split(b"\x00"):
        if not entry:
            continue
        try:
            rel_repo = entry.decode("utf-8")
        except UnicodeDecodeError:
            return False, {}
        rel_path = Path(rel_repo).relative_to(PACKAGE_REL)
        if "__pycache__" in rel_path.parts:
            continue
        show_ok, blob = _git_bytes(repo_root, "show", f"{tag}:{rel_repo}")
        if not show_ok:
            return False, {}
        files[rel_path] = blob
    return True, files


def release_state_violations(
    repo_root: Path = REPO_ROOT,
    *,
    cutting_release_tag: str | None = None,
    git_tags: Sequence[str] | None = None,
    tagged_tree_files: Mapping[Path, bytes] | None = None,
) -> list[str]:
    """Verify ``packages/cage-conformance/pyproject.toml`` ``[tool.cage.release]`` honesty.

    A declared version is either ``"published"`` (tag ``conformance-v<version>``
    exists and the package tree still matches it byte for byte) or
    ``"unreleased"`` (no such tag yet, and the version is strictly newer than
    every ``conformance-v*`` tag). Editing the package after a release therefore
    requires a version bump and ``status = "unreleased"``.
    """
    pyproject_rel = "packages/cage-conformance/pyproject.toml"
    pkg_pyproject = repo_root / pyproject_rel
    if not pkg_pyproject.is_file():
        return [f"{pyproject_rel} does not exist"]

    pkg_data = tomllib.loads(pkg_pyproject.read_text(encoding="utf-8"))
    pkg_version = str(pkg_data.get("project", {}).get("version", "")).strip()
    pkg_semver = _parse_semver(pkg_version)
    if pkg_semver is None:
        return [
            f"{pyproject_rel} project.version {pkg_version!r} "
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
            f"{pyproject_rel} [tool.cage.release].status must be "
            f"one of {sorted(VALID_RELEASE_STATUSES)!r} (got {status!r})"
        ]

    expected_tag = f"{CONFORMANCE_TAG_PREFIX}{pkg_version}"
    if git_tags is not None:
        tags = list(git_tags)
    else:
        git_ok, tags = _list_conformance_release_tags(repo_root)
        if not git_ok:
            return [
                "Unable to query git conformance-v* tags to verify "
                f"[tool.cage.release].status ({status!r} for version {pkg_version!r})"
            ]

    tag_semvers: list[tuple[tuple[int, int, int], str]] = []
    for tag in tags:
        if tag.startswith(CONFORMANCE_TAG_PREFIX):
            parsed = _parse_semver(tag.removeprefix(CONFORMANCE_TAG_PREFIX))
            if parsed is not None:
                tag_semvers.append((parsed, tag))

    if cutting_release_tag is not None:
        if cutting_release_tag != expected_tag:
            return [
                f"--cutting-release-tag {cutting_release_tag!r} does not match "
                f"expected tag {expected_tag!r} from {pyproject_rel}"
            ]
        other_semvers = [sv for sv, t in tag_semvers if t != expected_tag]
        if status == "unreleased":
            if other_semvers and pkg_semver <= max(other_semvers):
                highest_ver = ".".join(str(p) for p in max(other_semvers))
                return [
                    f"Cannot cut unreleased cage-conformance {pkg_version!r}: version "
                    f"must be strictly greater than existing release {highest_ver!r}"
                ]
            return []
        # status == "published" on an existing tag falls through to the tag+tree check

    errors: list[str] = []
    if status == "published":
        if expected_tag not in tags:
            return [
                f"{pyproject_rel} declares version {pkg_version!r} as "
                f"status='published', but git tag {expected_tag!r} does not exist "
                "(set status='unreleased' until the release tag is cut)"
            ]

        if tagged_tree_files is not None:
            tag_files = dict(tagged_tree_files)
        else:
            ok_tree, tag_files = _read_tagged_package_files(repo_root, expected_tag)
            if not ok_tree:
                return [
                    f"Failed to read {PACKAGE_REL} tree from git tag {expected_tag!r}"
                ]

        src_files = collect_package_files(repo_root / PACKAGE_REL)
        remedy = "(bump version and set [tool.cage.release].status = 'unreleased')"
        for rel_path in sorted(set(src_files) | set(tag_files)):
            if rel_path not in tag_files:
                errors.append(
                    f"{PACKAGE_REL / rel_path}: added since published tag "
                    f"{expected_tag!r} {remedy}"
                )
                continue
            if rel_path not in src_files:
                errors.append(
                    f"{PACKAGE_REL / rel_path}: removed since published tag "
                    f"{expected_tag!r} {remedy}"
                )
                continue
            src_sha = _sha256(src_files[rel_path])
            tag_sha = hashlib.sha256(tag_files[rel_path]).hexdigest()
            if src_sha != tag_sha:
                errors.append(
                    f"{PACKAGE_REL / rel_path}: SHA-256 {src_sha[:12]} diverges from "
                    f"published tag {expected_tag!r} ({tag_sha[:12]}) {remedy}"
                )
        return errors

    # status == "unreleased"
    if expected_tag in tags:
        errors.append(
            f"{pyproject_rel} still marks version {pkg_version!r} as "
            f"status='unreleased', but git tag {expected_tag!r} already exists "
            "(update [tool.cage.release].status = 'published')"
        )
    if tag_semvers:
        highest_semver, highest_tag = max(tag_semvers)
        if pkg_semver <= highest_semver:
            errors.append(
                f"Unreleased cage-conformance version {pkg_version!r} must be strictly "
                f"greater than latest published tag {highest_tag!r}"
            )
    return errors


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--cutting-release-tag",
        default=None,
        help=(
            "The conformance-v<version> tag being published right now; lets an "
            "'unreleased' version pass while its own tag already exists."
        ),
    )
    args = parser.parse_args(argv)
    errors = (
        sync_violations()
        + import_violations()
        + rule_coverage_violations()
        + internal_contract_violations()
        + release_state_violations(cutting_release_tag=args.cutting_release_tag)
    )
    for error in errors:
        print(f"❌ {error}", file=sys.stderr)
    if errors:
        return 1
    print(
        f"✅ cage-conformance: {len(SYNC_PAIRS)} proof modules byte-identical, "
        "no src/ or proof/ imports, rule coverage, package contracts and "
        "release state aligned"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
