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
   would only resolve inside a CAGE checkout).

Fix a sync failure by copying from ``proof/`` into the package, never the other
way round.

Usage:
    uv run python scripts/check_conformance_sync.py
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
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


def main() -> int:
    errors = (
        sync_violations()
        + import_violations()
        + rule_coverage_violations()
        + internal_contract_violations()
    )
    for error in errors:
        print(f"❌ {error}", file=sys.stderr)
    if errors:
        return 1
    print(
        f"✅ cage-conformance: {len(SYNC_PAIRS)} proof modules byte-identical, "
        "no src/ or proof/ imports, rule coverage and package contracts aligned"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
