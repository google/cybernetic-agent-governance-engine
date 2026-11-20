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

"""Discover and enforce the 24,000-byte truncation ceiling across repo agent files.

Coding agents (Google Antigravity, Claude Code, Cursor, Windsurf, GitHub
Copilot) inject instruction and rule files into context from multiple discovery
locations — not ``AGENTS.md`` alone. Observed context-loader truncation occurs at
~24,000 bytes (decimal 24 KB, 576 bytes below binary 24 KiB = 24,576), silently
dropping trailing rules with no runtime error (POAM-2026-224).

Rather than hard-coding ``AGENTS.md``, this gate discovers every repository file
matching an agent context-injection surface, enforces a non-vacuous corpus floor
(``MIN_INJECTED_FILES = 3``, leaving headroom for workflow churn while catching
discovery collapse), and fails closed if any discovered file is empty (0 B) or
exceeds ``MAX_BYTES`` (24,000 B).

Scope boundary: host-level global instruction files outside the repository tree
(for example ``~/.gemini/config/rules/*.md`` or ``~/.claude/``) are also injected
into agent context under the same truncation ceiling, but sit outside any
repository-scoped CI or pre-commit gate.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[1]

MAX_BYTES = (
    24000  # Observed ~24,000-byte truncation cutoff (not binary 24 KiB = 24,576)
)
MIN_INJECTED_FILES = (
    3  # Catches discovery collapse while allowing normal workflow churn
)

InjectedFileKind = Literal[
    "directory_rule",
    "workspace_rule",
    "skill",
    "agent",
    "workflow",
    "copilot_instruction",
]

DIRECTORY_RULE_FILENAMES: frozenset[str] = frozenset(
    {
        "AGENTS.md",
        "GEMINI.md",
        "CLAUDE.md",
        ".cursorrules",
        ".windsurfrules",
        ".clinerules",
    }
)

CUSTOMIZATION_DIRS: frozenset[str] = frozenset(
    {
        ".agents",
        "_agents",
        ".gemini",
        ".claude",
        ".cursor",
        ".windsurf",
        ".roo",
    }
)

PRUNED_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "third_party",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".terraform",
        "build",
        "dist",
        "scratch",
        "tmp",
        "artifacts",
    }
)


class CorpusFloorError(RuntimeError):
    """Raised when discovered agent-injected files fall below ``MIN_INJECTED_FILES``."""


@dataclass(frozen=True)
class InjectedAgentFile:
    """An agent instruction, rule, skill, agent, or workflow file discovered on disk."""

    rel_path: str
    kind: InjectedFileKind
    size_bytes: int


def _classify_customization_subpath(
    subparts: tuple[str, ...],
) -> InjectedFileKind | None:
    """Classify a relative path inside a customization root (e.g. ``.agents/...``)."""
    if not subparts:
        return None
    if subparts[0] == "plugins" and len(subparts) >= 3:
        subparts = subparts[2:]
    if len(subparts) < 2:
        return None

    top = subparts[0]
    leaf = subparts[-1]
    if top == "rules" and leaf.endswith((".md", ".mdc")):
        return "workspace_rule"
    if top == "skills" and leaf == "SKILL.md":
        return "skill"
    if top == "agents" and leaf.endswith(".md"):
        return "agent"
    if top in {"workflows", "commands"} and leaf.endswith(".md"):
        return "workflow"
    return None


def classify_injected_rel_path(rel_posix: str) -> InjectedFileKind | None:
    """Return the injection surface kind for ``rel_posix``, or ``None`` if not injected."""
    parts = tuple(p for p in rel_posix.split("/") if p)
    if not parts:
        return None

    leaf = parts[-1]
    if leaf in DIRECTORY_RULE_FILENAMES:
        return "directory_rule"

    if parts[0] == ".github":
        if len(parts) == 2 and leaf == "copilot-instructions.md":
            return "copilot_instruction"
        if len(parts) >= 3 and parts[1] == "instructions" and leaf.endswith(".md"):
            return "copilot_instruction"

    for idx, part in enumerate(parts[:-1]):
        if part in CUSTOMIZATION_DIRS:
            kind = _classify_customization_subpath(parts[idx + 1 :])
            if kind is not None:
                return kind

    return None


def discover_injected_agent_files(
    repo_root: Path = DEFAULT_REPO_ROOT,
) -> list[InjectedAgentFile]:
    """Discover all agent-injected instruction/rule/skill/workflow files under ``repo_root``."""
    root = repo_root.resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Repository root does not exist: {root}")

    discovered: list[InjectedAgentFile] = []
    for current_dir, dirnames, filenames in os.walk(root, topdown=True):
        dirnames[:] = sorted(d for d in dirnames if d not in PRUNED_DIR_NAMES)
        cur_path = Path(current_dir)
        for filename in sorted(filenames):
            full_path = cur_path / filename
            if not full_path.is_file():
                continue
            rel_posix = full_path.relative_to(root).as_posix()
            kind = classify_injected_rel_path(rel_posix)
            if kind is None:
                continue
            discovered.append(
                InjectedAgentFile(
                    rel_path=rel_posix,
                    kind=kind,
                    size_bytes=full_path.stat().st_size,
                )
            )

    discovered.sort(key=lambda item: item.rel_path)
    return discovered


def check_injected_agent_files(
    repo_root: Path = DEFAULT_REPO_ROOT,
    *,
    max_bytes: int = MAX_BYTES,
    min_files: int = MIN_INJECTED_FILES,
) -> tuple[list[InjectedAgentFile], list[str]]:
    """Discover and validate all agent-injected files under ``repo_root``."""
    files = discover_injected_agent_files(repo_root)
    if len(files) < min_files:
        raise CorpusFloorError(
            f"Agent-injected file corpus floor breach: discovered {len(files)} file(s) "
            f"under {repo_root}, expected >= {min_files}."
        )

    violations: list[str] = []
    for item in files:
        if item.size_bytes == 0:
            violations.append(
                f"{item.rel_path} ({item.kind}): file is empty (0 bytes)."
            )
        elif item.size_bytes > max_bytes:
            excess = item.size_bytes - max_bytes
            violations.append(
                f"{item.rel_path} ({item.kind}): {item.size_bytes:,} bytes exceeds "
                f"{max_bytes:,}-byte truncation cutoff by {excess:,} bytes."
            )
    return files, violations


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Discover and check size limits across all agent-injected files."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=DEFAULT_REPO_ROOT,
        help="Repository root to scan (defaults to CAGE root).",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=MAX_BYTES,
        help=f"Maximum size in bytes per file (default: {MAX_BYTES}).",
    )
    parser.add_argument(
        "--min-files",
        type=int,
        default=MIN_INJECTED_FILES,
        help=f"Minimum discovered file count floor (default: {MIN_INJECTED_FILES}).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="List every discovered file and its percentage of the truncation cutoff.",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        files, violations = check_injected_agent_files(
            args.repo_root,
            max_bytes=args.max_bytes,
            min_files=args.min_files,
        )
    except (FileNotFoundError, CorpusFloorError) as exc:
        print(f"❌ Error: {exc}")
        return 1

    if args.verbose:
        for item in files:
            pct = (item.size_bytes / args.max_bytes) * 100 if args.max_bytes else 0.0
            print(
                f"  • {item.rel_path} [{item.kind}]: "
                f"{item.size_bytes:,} / {args.max_bytes:,} B ({pct:.1f}%)"
            )

    if violations:
        print(
            f"❌ Agent context size gate FAILED: {len(violations)} violation(s) across "
            f"{len(files)} discovered file(s):"
        )
        for violation in violations:
            print(f"   - {violation}")
        print(
            "   Exceeding ~24,000 bytes causes coding agents to silently truncate rules past the cut-off."
        )
        return 1

    largest = max(files, key=lambda item: item.size_bytes)
    pct = (largest.size_bytes / args.max_bytes) * 100
    print(
        f"✅ Agent context size check passed: {len(files)} discovered file(s) <= "
        f"{args.max_bytes:,} bytes (largest: {largest.rel_path} at {largest.size_bytes:,} B, {pct:.1f}%)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
