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

"""Model-free install gate (POAM-2026-168).

CAGE claims that no model sits in its decision path. This gate checks that
claim at the level a reviewer sees it first: the dependency set.

1. **Base install.** The closure of ``[project.dependencies]``, resolved from
   ``uv.lock``, contains no LLM client, model runtime or LLM framework.
2. **Gateway image.** The same holds for the closure of the extras that
   ``src/gateway/Dockerfile`` installs with ``uv sync``. No ``pip install``
   line in that Dockerfile may name one of those packages either. The image is
   what deploys, and it can diverge from the base install silently.
3. **The import gate's own configuration.** G3's ``FORBIDDEN_VENDOR_SDKS``
   (``scripts/check_import_boundaries.py``) must still list every LLM client
   and model runtime. Otherwise the kernel import check could be narrowed
   later and nothing would notice. That is how ``scripts/`` once left Bandit's
   scope (POAM-2026-163).

The closure ignores environment markers, so it is a superset across
platforms. A forbidden package behind any marker fails the gate.

Stdlib only, so it runs as a local pre-commit gate and in CI.
Exit 0: all three hold. Exit 1: a violation, each printed with the path that
pulls the package in.
"""

from __future__ import annotations

import argparse
import ast
import re
import shlex
import sys
from collections import deque
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import tomllib

REPO_ROOT = Path(__file__).resolve().parent.parent

# Distributions that put a model, a model client or an LLM framework in an
# install (PEP 503 normalized names).
MODEL_PACKAGES: frozenset[str] = frozenset(
    {
        # LLM API clients
        "litellm",
        "openai",
        "anthropic",
        "google-genai",
        "google-generativeai",
        "google-adk",
        "mistralai",
        "cohere",
        # LLM frameworks
        "langchain",
        "langchain-core",
        "langchain-openai",
        "langchain-community",
        "langgraph",
        "nemoguardrails",
        # Model runtimes, serving and tokenizers
        "transformers",
        "sentence-transformers",
        "vllm",
        "torch",
        "tiktoken",
        "tokenizers",
        "huggingface-hub",
        "onnxruntime",
        "fastembed",
    }
)

# Import names G3 must forbid in the kernel: the LLM clients and model
# runtimes. The kernel's agent-framework adapters (``langgraph``,
# ``langchain_core``, ``langchain_mcp_adapters``) are lazy, agent-side
# integrations and are deliberately not listed.
KERNEL_FORBIDDEN_IMPORTS: frozenset[str] = frozenset(
    {
        "openai",
        "litellm",
        "anthropic",
        "google.genai",
        "google.generativeai",
        "google.adk",
        "mistralai",
        "cohere",
        "langchain",
        "langchain_openai",
        "langchain_community",
        "nemoguardrails",
        "transformers",
        "sentence_transformers",
        "vllm",
        "torch",
        "tiktoken",
        "tokenizers",
        "huggingface_hub",
        "onnxruntime",
        "fastembed",
    }
)

_EXTRA_FLAG = re.compile(r"--extra(?:=|\s+)([A-Za-z0-9_.-]+)")


def normalize(name: str) -> str:
    """PEP 503 normalized distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _load_lock(lock_path: Path) -> dict[str, list[dict[str, Any]]]:
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    by_name: dict[str, list[dict[str, Any]]] = {}
    for package in lock.get("package", []):
        by_name.setdefault(normalize(package["name"]), []).append(package)
    return by_name


def closure(
    by_name: Mapping[str, list[dict[str, Any]]], root: str, extras: Iterable[str]
) -> dict[str, list[str]]:
    """Every package the root (with ``extras``) resolves to, with one requiring path."""
    root = normalize(root)
    start = (root, tuple(sorted(extras)))
    paths: dict[str, list[str]] = {root: [root]}
    seen = {start}
    queue = deque([start])
    while queue:
        name, active = queue.popleft()
        for package in by_name.get(name, []):
            deps = list(package.get("dependencies", []))
            optional = package.get("optional-dependencies", {})
            for extra in active:
                deps += optional.get(extra, [])
            for dep in deps:
                dep_name = normalize(dep["name"])
                key = (dep_name, tuple(sorted(dep.get("extra", []))))
                if key in seen:
                    continue
                seen.add(key)
                paths.setdefault(dep_name, [*paths[name], dep_name])
                queue.append(key)
    return paths


def _instructions(dockerfile: str) -> list[str]:
    """Dockerfile lines with continuations joined and comments dropped."""
    joined = dockerfile.replace("\\\n", " ")
    return [line for line in joined.splitlines() if not line.lstrip().startswith("#")]


def dockerfile_extras(dockerfile: str) -> tuple[set[str], list[str]]:
    """Extras the Dockerfile's ``uv sync`` installs, and any parse problems."""
    problems: list[str] = []
    extras: set[str] = set()
    sync_lines = [
        line for line in _instructions(dockerfile) if re.search(r"\buv\s+sync\b", line)
    ]
    if not sync_lines:
        problems.append("no `uv sync` line found; the install set cannot be verified")
    for line in sync_lines:
        if "--all-extras" in line:
            problems.append(
                f"`uv sync --all-extras` installs every extra: {line.strip()}"
            )
        extras.update(_EXTRA_FLAG.findall(line))
    return extras, problems


def dockerfile_pip_installs(dockerfile: str) -> list[str]:
    """Forbidden packages named by any ``pip install`` in the Dockerfile."""
    found: list[str] = []
    for line in _instructions(dockerfile):
        if not re.search(r"\bpip\s+install\b", line):
            continue
        try:
            tokens = shlex.split(line, comments=True)
        except ValueError:
            tokens = line.split()
        for token in tokens:
            if token.startswith("-") or "://" in token or "/" in token:
                continue
            requirement = re.split(r"[\[<>=!~;@ ]", token, maxsplit=1)[0]
            if requirement and normalize(requirement) in MODEL_PACKAGES:
                found.append(normalize(requirement))
    return found


def forbidden_vendor_sdks(boundaries_source: str) -> tuple[set[str] | None, str]:
    """``FORBIDDEN_VENDOR_SDKS`` as a literal set of strings, or a reason it isn't one.

    Exactly one module-level assignment is accepted. A second assignment, or
    an augmented one, could change the list G3 uses while the first literal
    still looks complete.
    """
    tree = ast.parse(boundaries_source)
    values: list[ast.expr | None] = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value: ast.expr | None = node.value
        elif isinstance(node, ast.AnnAssign | ast.AugAssign):
            names = [node.target.id] if isinstance(node.target, ast.Name) else []
            value = node.value if isinstance(node, ast.AnnAssign) else None
        else:
            continue
        if "FORBIDDEN_VENDOR_SDKS" in names:
            values.append(value)
    if not values:
        return None, "FORBIDDEN_VENDOR_SDKS is not defined"
    if len(values) > 1:
        return None, "FORBIDDEN_VENDOR_SDKS is assigned more than once"
    literal = values[0]
    if not isinstance(literal, ast.Tuple | ast.List | ast.Set) or not all(
        isinstance(e, ast.Constant) and isinstance(e.value, str) for e in literal.elts
    ):
        return None, "FORBIDDEN_VENDOR_SDKS is not a literal sequence of strings"
    return {e.value for e in literal.elts if isinstance(e, ast.Constant)}, ""


def check(
    pyproject_path: Path,
    lock_path: Path,
    dockerfile_path: Path,
    boundaries_path: Path,
) -> list[str]:
    """Return every violation of the three properties (empty when all hold)."""
    violations: list[str] = []
    project = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))["project"]
    root = normalize(project["name"])
    by_name = _load_lock(lock_path)
    if root not in by_name:
        return [f"uv.lock has no entry for the project ({root}); run `uv lock`"]

    declared_extras = {
        normalize(e)
        for package in by_name[root]
        for e in package.get("optional-dependencies", {})
    }

    def report(label: str, extras: Iterable[str]) -> None:
        paths = closure(by_name, root, extras)
        for name in sorted(MODEL_PACKAGES & set(paths)):
            violations.append(f"{label} resolves {name} via {' -> '.join(paths[name])}")

    report("base install", ())

    dockerfile = dockerfile_path.read_text(encoding="utf-8")
    extras, problems = dockerfile_extras(dockerfile)
    violations += [f"{dockerfile_path.name}: {p}" for p in problems]
    unknown = sorted(
        normalize(e) for e in extras if normalize(e) not in declared_extras
    )
    violations += [
        f"{dockerfile_path.name}: extra {e!r} is not declared in uv.lock"
        for e in unknown
    ]
    report(f"gateway image (extras: {', '.join(sorted(extras)) or 'none'})", extras)
    violations += [
        f"{dockerfile_path.name}: `pip install` names {name}"
        for name in dockerfile_pip_installs(dockerfile)
    ]

    listed, reason = forbidden_vendor_sdks(boundaries_path.read_text(encoding="utf-8"))
    if listed is None:
        violations.append(f"{boundaries_path.name}: {reason}; G3 cannot be verified")
    else:
        for name in sorted(KERNEL_FORBIDDEN_IMPORTS - listed):
            violations.append(
                f"{boundaries_path.name}: FORBIDDEN_VENDOR_SDKS no longer lists "
                f"{name!r}, so the kernel could import it unchecked"
            )
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)
    root: Path = args.root
    violations = check(
        root / "pyproject.toml",
        root / "uv.lock",
        root / "src" / "gateway" / "Dockerfile",
        root / "scripts" / "check_import_boundaries.py",
    )
    if violations:
        print("❌ Model-free install gate failed (POAM-2026-168):")
        for violation in violations:
            print(f"   • {violation}")
        return 1
    print(
        "✅ Model-free install gate: the base install and the gateway image resolve "
        f"none of {len(MODEL_PACKAGES)} model packages; G3 forbids all "
        f"{len(KERNEL_FORBIDDEN_IMPORTS)} LLM client and runtime imports."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
