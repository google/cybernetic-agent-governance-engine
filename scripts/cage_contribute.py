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

"""CAGE Contributor CLI (`scripts/cage_contribute.py`).

Unified, Google-standard contributor automation CLI enforcing the rules, workflows,
commit standards, branch naming, and architectural gates defined in CONTRIBUTING.md
and AGENTS.md.

Standard Library Only:
    Requires zero third-party packages (uses pure Python 3 standard library:
    argparse, subprocess, re, pathlib, shutil, sys, os, json, dataclasses, enum).

Subcommands:
    setup              Configure git hooks, commit template, prerequisites, and .env.
    branch             Create and checkout a strictly validated CAGE feature branch.
    validate-commit    Validate Conventional Commits v1.0.0 message from string or file.
    commit             Validate commit message, check license headers, and git commit.
    check              Run pre-commit architectural verification gates (--fast / --all).
    cloudbuild         Submit or dry-run immutable Cloud Build container image jobs.
    verify-service-sync Verify service catalogue consistency across scripts and Terraform.
    scaffold           Scaffold ADR-009 tiers, Layer 3 seams, or domain plugins.
    pr                 Validate branch readiness, clean tree, squash-merge guard, and open PR.
    release-tag        Validate tag format and CHANGELOG before creating an annotated release tag.
    doctor             Diagnose contributor environment and toolchain health.

Usage:
    python scripts/cage_contribute.py <subcommand> [options]
"""

from __future__ import annotations

import argparse
import ast
import enum
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Reconfigure stdout/stderr to UTF-8 on Windows with error replacement to prevent cp1252 crashes
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(errors="replace")

# ---------------------------------------------------------------------------
# Project Standards & Constants (AGENTS.md & CONTRIBUTING.md)
# ---------------------------------------------------------------------------

CONVENTIONAL_TYPES: frozenset[str] = frozenset(
    {
        "feat",
        "fix",
        "docs",
        "style",
        "refactor",
        "perf",
        "test",
        "chore",
        "ci",
        "revert",
    }
)

CONVENTIONAL_SCOPES: frozenset[str] = frozenset(
    {
        "gateway",
        "compliance",
        "infra",
        "governance",
        "tests",
        "docs",
        "ci",
        "agentsight",
        "advisor",
        "nemo",
        "opa",
        "ftra",
        "finance",
        "healthcare",
        "security",
        "imports",
    }
)

# CAGE branch regex: (type)/(description) or hotfix/(version)-(description)
# Description must be lowercase kebab-case, <= 30 chars after prefix.
BRANCH_REGEX: re.Pattern[str] = re.compile(
    r"^(feat|fix|docs|refactor|ci|test|chore|spike)/[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?$|^hotfix/v?[0-9]+\.[0-9]+\.[0-9]+-[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?$"
)

# Common past-tense, 3rd-person, or continuous gerund non-imperative verbs to reject
NON_IMPERATIVE_VERBS: frozenset[str] = frozenset(
    {
        "added",
        "adds",
        "adding",
        "fixed",
        "fixes",
        "fixing",
        "updated",
        "updates",
        "updating",
        "created",
        "creates",
        "creating",
        "removed",
        "removes",
        "removing",
        "changed",
        "changes",
        "changing",
        "implemented",
        "implements",
        "implementing",
        "refactored",
        "refactors",
        "refactoring",
        "deleted",
        "deletes",
        "deleting",
        "modified",
        "modifies",
        "modifying",
        "cleaned",
        "cleans",
        "cleaning",
        "patched",
        "patches",
        "patching",
        "improved",
        "improves",
        "improving",
        "allowed",
        "allows",
        "allowing",
        "prevented",
        "prevents",
        "preventing",
        "resolved",
        "resolves",
        "resolving",
        "adjusted",
        "adjusts",
        "adjusting",
    }
)

PROTECTED_BRANCHES: frozenset[str] = frozenset({"main", "master"})
PROTECTED_PREFIXES: tuple[str, ...] = ("rc-v", "release/")

APACHE_LICENSE_HEADER: str = """# Copyright 2026 Google LLC
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
"""

APACHE_LICENSE_HEADER_TS: str = APACHE_LICENSE_HEADER.replace("#", "//")

FIRST_PARTY_SERVICES: tuple[str, ...] = (
    "gateway",
    "agentsight-ui",
    "compliance-bridge",
    "governed-financial-advisor",
    "nemo-guardrails",
    "vllm-streamer",
    "lula",
)

# ---------------------------------------------------------------------------
# Platform & Git Utilities
# ---------------------------------------------------------------------------


def get_git_executable() -> str:
    """Resolve a functional git executable.

    Checks shutil.which, then tests execution. On Windows, if a shim is broken
    or missing, falls back to common Git installation paths.
    """
    candidates: list[str] = []
    which_git = shutil.which("git")
    if which_git:
        candidates.append(which_git)

    if sys.platform == "win32":
        candidates.extend(
            [
                r"C:\Program Files\Git\cmd\git.exe",
                r"C:\Program Files\Git\bin\git.exe",
                r"C:\Program Files (x86)\Git\cmd\git.exe",
                os.path.join(
                    os.environ.get("LOCALAPPDATA", ""),
                    "Programs",
                    "Git",
                    "cmd",
                    "git.exe",
                ),
            ]
        )
    else:
        candidates.extend(["/usr/bin/git", "/usr/local/bin/git"])

    for cand in candidates:
        if not cand:
            continue
        # Verify candidate actually runs
        try:
            res = subprocess.run(
                [cand, "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
            if res.returncode == 0:
                return cand
        except Exception:
            continue

    return "git"


def run_cmd(
    args: Sequence[str],
    *,
    cwd: Path | str | None = None,
    env: dict[str, str] | None = None,
    capture_output: bool = True,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Execute a subprocess command with zero shell=True and process-scoped environment.

    Never modifies system/user PATH or registry keys.
    """
    merged_env = os.environ.copy()
    merged_env.setdefault("PYTHONIOENCODING", "utf-8")
    merged_env.setdefault("PYTHONUTF8", "1")
    if env:
        merged_env.update(env)

    return subprocess.run(
        list(args),
        cwd=str(cwd) if cwd else None,
        env=merged_env,
        capture_output=capture_output,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=check,
    )


def find_repo_root(start_dir: Path | None = None) -> Path:
    """Find the root directory of the CAGE git repository."""
    curr = (start_dir or Path.cwd()).resolve()
    for parent in [curr, *curr.parents]:
        if (parent / ".git").exists() or (parent / "pyproject.toml").is_file():
            return parent
    return curr


def get_current_branch(repo_root: Path) -> str:
    """Return the name of the currently checked out branch."""
    git_bin = get_git_executable()
    res = run_cmd([git_bin, "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_root)
    if res.returncode == 0:
        return res.stdout.strip()
    return "UNKNOWN"


def get_short_sha(repo_root: Path) -> str:
    """Return the immutable short commit SHA of HEAD."""
    git_bin = get_git_executable()
    res = run_cmd([git_bin, "rev-parse", "--short", "HEAD"], cwd=repo_root)
    if res.returncode == 0:
        return res.stdout.strip()
    return "UNKNOWN"


def is_working_tree_clean(repo_root: Path) -> bool:
    """Check if git working tree has zero uncommitted changes."""
    git_bin = get_git_executable()
    res = run_cmd([git_bin, "status", "--porcelain"], cwd=repo_root)
    if res.returncode == 0:
        return len(res.stdout.strip()) == 0
    return False


def get_git_hooks_dir(repo_root: Path) -> Path:
    """Resolve git hooks directory, supporting worktrees and submodules."""
    git_bin = get_git_executable()
    try:
        res = run_cmd([git_bin, "rev-parse", "--git-path", "hooks"], cwd=repo_root)
        if res.returncode == 0 and res.stdout and res.stdout.strip():
            hooks_path = Path(res.stdout.strip())
            if not hooks_path.is_absolute():
                hooks_path = (repo_root / hooks_path).resolve()
            return hooks_path
    except (FileNotFoundError, OSError):
        pass

    dot_git = repo_root / ".git"
    if dot_git.is_file():
        try:
            content = dot_git.read_text(encoding="utf-8").strip()
            if content.startswith("gitdir:"):
                gitdir = Path(content.split("gitdir:", 1)[1].strip())
                if not gitdir.is_absolute():
                    gitdir = (repo_root / gitdir).resolve()
                if (gitdir / "hooks").is_dir():
                    return gitdir / "hooks"
                if (gitdir.parent.parent / "hooks").is_dir():
                    return gitdir.parent.parent / "hooks"
                return gitdir / "hooks"
        except Exception:
            pass

    return repo_root / ".git" / "hooks"


# ---------------------------------------------------------------------------
# Validation Engines (Branch & Conventional Commits v1.0.0)
# ---------------------------------------------------------------------------


def validate_branch_name(branch: str) -> tuple[bool, str]:
    """Validate a branch name against CAGE standards.

    Returns (is_valid, error_reason).
    """
    if not branch or not isinstance(branch, str):
        return False, "Branch name cannot be empty."

    if branch in PROTECTED_BRANCHES:
        return False, (
            f"Direct work on protected branch '{branch}' is not allowed.\n"
            "Please create a feature branch instead:\n"
            "git checkout -b <type>/<description>\n"
            "After committing your changes, push this branch and open a pull request."
        )

    for prefix in PROTECTED_PREFIXES:
        if branch.startswith(prefix):
            return False, (
                f"Branch name '{branch}' targets a protected release prefix ('{prefix}*').\n"
                "Release branches require an admin-created ruleset and cannot be branched directly."
            )

    if not BRANCH_REGEX.match(branch):
        prefix_part = branch.split("/")[0] if "/" in branch else ""
        desc_part = branch.split("/", 1)[1] if "/" in branch else ""

        reasons = []
        if "/" not in branch:
            reasons.append(
                "Missing required '<type>/' prefix (e.g. feat/, fix/, docs/)."
            )
        elif prefix_part not in {
            "feat",
            "fix",
            "docs",
            "refactor",
            "ci",
            "test",
            "chore",
            "spike",
            "hotfix",
        }:
            reasons.append(
                f"Invalid type prefix '{prefix_part}'. Must be one of: "
                "feat, fix, docs, refactor, ci, test, chore, spike, hotfix."
            )

        if desc_part:
            if len(desc_part) > 30:
                reasons.append(
                    f"Description length is {len(desc_part)} chars (maximum allowed is 30 chars)."
                )
            if not re.match(r"^[a-z0-9-]+$", desc_part):
                reasons.append(
                    "Description must be lowercase kebab-case (letters, numbers, hyphens only; no underscores or uppercase)."
                )
            if desc_part.startswith("-") or desc_part.endswith("-"):
                reasons.append("Description must not start or end with a hyphen.")

        reason_str = (
            " ".join(reasons)
            if reasons
            else "Does not match pattern '<type>/<kebab-case-desc-under-30-chars>'."
        )
        return False, f"Branch name '{branch}' violates naming convention: {reason_str}"

    return True, ""


def validate_commit_message(msg: str) -> tuple[bool, list[str]]:
    """Validate a commit message against Conventional Commits v1.0.0 and CAGE rules.

    Returns (is_valid, list_of_errors).
    """
    errors: list[str] = []
    lines = msg.splitlines()

    # Strip empty leading/trailing lines
    non_comment_lines = [l for l in lines if not l.strip().startswith("#")]
    while non_comment_lines and not non_comment_lines[0].strip():
        non_comment_lines.pop(0)
    while non_comment_lines and not non_comment_lines[-1].strip():
        non_comment_lines.pop()

    if not non_comment_lines:
        return True, []  # Allow empty (e.g. amend with no change)

    subject = non_comment_lines[0].strip()

    # Exemption for git merge commits
    if (
        subject.startswith("Merge branch ")
        or subject.startswith("Merge pull request ")
        or subject.startswith("Merge remote-tracking branch ")
    ):
        return True, []

    # Subject line length check (<= 72 chars)
    if len(subject) > 72:
        errors.append(
            f"Subject line exceeds 72 characters ({len(subject)} chars): '{subject[:69]}...'"
        )

    # Trailing period check
    if subject.endswith("."):
        errors.append("Subject line must not end with a trailing period ('.').")

    # Conventional Commits format parser
    # Match: <type>(<scope>)?: <summary> or <type>(<scope>)?!: <summary>
    m = re.match(r"^([a-z]+)(?:\(([a-z0-9/_-]+)\))?(!)?:\s+(.*)$", subject)
    if not m:
        errors.append(
            f"Subject line '{subject}' does not follow Conventional Commits format:\n"
            "  Expected: <type>(<scope>): <summary>\n"
            "  Types:    feat | fix | docs | style | refactor | perf | test | chore | ci | revert\n"
            "  Scopes:   gateway | compliance | infra | governance | tests | docs | ci |\n"
            "            agentsight | advisor | nemo | opa | ftra | finance | healthcare | security | imports"
        )
        return False, errors

    commit_type, commit_scope, has_bang, summary = m.groups()

    if commit_type not in CONVENTIONAL_TYPES:
        errors.append(
            f"Invalid commit type '{commit_type}'. Allowed types: {', '.join(sorted(CONVENTIONAL_TYPES))}."
        )

    if commit_scope and commit_scope not in CONVENTIONAL_SCOPES:
        errors.append(
            f"Invalid commit scope '{commit_scope}'. Allowed scopes: {', '.join(sorted(CONVENTIONAL_SCOPES))}."
        )

    # Imperative mood check on summary
    first_word_match = re.match(r"^([A-Za-z]+)", summary)
    if first_word_match:
        first_word = first_word_match.group(1).lower()
        if first_word in NON_IMPERATIVE_VERBS:
            errors.append(
                f"Subject summary begins with non-imperative verb '{first_word}'.\n"
                "  Use imperative mood ('add' instead of 'added'/'adds', 'fix' instead of 'fixed'/'fixes')."
            )

    # Blank line separation between subject and body
    if len(non_comment_lines) > 1:
        second_line = non_comment_lines[1]
        if second_line.strip() != "":
            errors.append(
                "A blank line must separate the commit subject from the commit body."
            )

    # Bidirectional breaking change invariant
    # ! after type/scope IFF BREAKING CHANGE: footer is present
    has_breaking_footer = any(
        l.startswith("BREAKING CHANGE:") or l.startswith("BREAKING-CHANGE:")
        for l in non_comment_lines[1:]
    )

    if has_bang and not has_breaking_footer:
        errors.append(
            "Breaking change exclamation mark '!' found after type/scope in subject, "
            "but missing required 'BREAKING CHANGE:' footer in commit body."
        )
    elif has_breaking_footer and not has_bang:
        errors.append(
            "'BREAKING CHANGE:' footer present in body, but subject line lacks the required "
            "'!' indicator after type/scope (e.g. feat(gateway)!: <summary>)."
        )

    return len(errors) == 0, errors


# ---------------------------------------------------------------------------
# Subcommand Handlers
# ---------------------------------------------------------------------------


def cmd_setup(args: argparse.Namespace) -> int:
    """Install git commit template, hooks, verify prerequisites, and init .env."""
    repo_root = find_repo_root()
    git_bin = get_git_executable()
    print(
        f"🔧 Initializing Google-Standard CAGE Contributor Environment at: {repo_root}"
    )

    # 1. Commit template
    gitmessage_path = repo_root / ".gitmessage"
    if not gitmessage_path.exists():
        template_content = """# <type>(<scope>): <short summary ≤ 72 chars>
#
# Types: feat | fix | docs | style | refactor | perf | test | chore | ci | revert
# Scopes: gateway | compliance | infra | governance | tests | docs | ci | agentsight | advisor | nemo | opa | ftra | finance | healthcare | security | imports
#
# Explain *what* and *why*, not how.
# Breaking change: add '!' after type/scope AND add 'BREAKING CHANGE:' in footer.
"""
        gitmessage_path.write_text(template_content, encoding="utf-8")
        print("  ✅ Created .gitmessage template.")

    run_cmd([git_bin, "config", "commit.template", str(gitmessage_path)], cwd=repo_root)
    print("  ✅ Configured commit.template in git config.")

    # 2. Hooks directory
    hooks_dir = get_git_hooks_dir(repo_root)
    hooks_dir.mkdir(parents=True, exist_ok=True)

    # 2a. commit-msg hook
    commit_msg_hook = hooks_dir / "commit-msg"
    commit_msg_script = """#!/usr/bin/env bash
# CAGE commit-msg hook — delegates to cage_contribute.py
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
if command -v python3 &>/dev/null; then
  python3 "${{REPO_ROOT}}/scripts/cage_contribute.py" validate-commit "$1"
elif command -v python &>/dev/null; then
  python "${{REPO_ROOT}}/scripts/cage_contribute.py" validate-commit "$1"
else
  # Minimal shell fallback if python is unavailable
  SUBJECT=$(head -n 1 "$1" | grep -v '^#')
  PATTERN='^(feat|fix|docs|style|refactor|perf|test|chore|ci|revert)(\\([a-z0-9/_-]+\\))?(!)?: .{{1,72}}$'
  if ! echo "$SUBJECT" | grep -qE "$PATTERN"; then
    echo "❌ Commit message does not follow Conventional Commits format."
    exit 1
  fi
fi
"""
    commit_msg_hook.write_text(commit_msg_script, encoding="utf-8")
    try:
        commit_msg_hook.chmod(
            commit_msg_hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        )
    except Exception:
        pass
    print("  ✅ Installed .git/hooks/commit-msg hook.")

    # 2b. pre-push hook
    pre_push_hook = hooks_dir / "pre-push"
    pre_push_script = """#!/usr/bin/env bash
# CAGE pre-push hook — refuses direct push to protected branches
set -uo pipefail
PROTECTED_BRANCHES="main master"
PATTERN='^(feat|fix|docs|refactor|ci|test|chore|spike)/[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?$|^hotfix/v?[0-9]+\\.[0-9]+\\.[0-9]+-[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?$'

status=0
while read -r _local_ref local_oid remote_ref _remote_oid; do
  case "$remote_ref" in
    refs/heads/*) branch="${remote_ref#refs/heads/}" ;;
    *) continue ;;
  esac

  for protected in $PROTECTED_BRANCHES; do
    if [[ "$branch" == "$protected" ]]; then
      echo ""
      echo "❌ Direct push to '$branch' is not allowed."
      echo "   Please create a feature branch and open a pull request:"
      echo "   git checkout -b feat/<your-feature>"
      echo ""
      status=1
      continue 2
    fi
  done

  if [[ -z "${local_oid//0/}" ]]; then
    continue
  fi

  if ! printf '%s\\n' "$branch" | grep -qE "$PATTERN"; then
    echo ""
    echo "❌ Branch name '$branch' does not follow CAGE naming conventions."
    echo "   Pattern: feat/<desc>, fix/<desc>, docs/<desc>, etc. (<= 30 chars description)."
    echo ""
    status=1
  fi
done

exit "$status"
"""
    pre_push_hook.write_text(pre_push_script, encoding="utf-8")
    try:
        pre_push_hook.chmod(
            pre_push_hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        )
    except Exception:
        pass
    print("  ✅ Installed .git/hooks/pre-push hook.")

    # 3. Environment file .env initialization
    env_file = repo_root / ".env"
    env_example = repo_root / ".env.example"
    if not env_file.exists():
        if env_example.exists():
            shutil.copy(env_example, env_file)
            print(
                "  ✅ Initialized .env from .env.example (please review and populate secrets)."
            )
        else:
            env_file.write_text(
                "# CAGE Local Environment Variables\n", encoding="utf-8"
            )
            print("  ✅ Created new .env file.")
    else:
        print("  [INFO] Existing .env preserved (zero-overwrite guarantee).")

    # 4. Optional uv sync
    if getattr(args, "sync", False):
        uv_bin = shutil.which("uv")
        if uv_bin:
            print("  📦 Running 'uv sync --all-groups --all-extras'...")
            run_cmd(
                [uv_bin, "sync", "--all-groups", "--all-extras"],
                cwd=repo_root,
                capture_output=False,
            )
        else:
            print(
                "  ⚠️  'uv' not found on PATH. Install uv to run dependency synchronization."
            )

    print("\n✨ Setup complete! Developer environment is ready.")
    return 0


def cmd_branch(args: argparse.Namespace) -> int:
    """Validate and checkout a new CAGE feature branch."""
    repo_root = find_repo_root()
    git_bin = get_git_executable()

    branch_name: str
    if args.description:
        branch_name = f"{args.type}/{args.description}"
    else:
        branch_name = args.type

    # Validate branch name
    valid, reason = validate_branch_name(branch_name)
    if not valid:
        print(f"\n❌ Invalid branch name: {branch_name}")
        print(f"   {reason}\n")
        return 1

    base_branch = args.base or "main"
    print(
        f"🌿 Creating and checking out branch '{branch_name}' from '{base_branch}'..."
    )

    res = run_cmd([git_bin, "checkout", "-b", branch_name, base_branch], cwd=repo_root)
    if res.returncode != 0:
        # If branch already exists, try standard checkout
        res_checkout = run_cmd([git_bin, "checkout", branch_name], cwd=repo_root)
        if res_checkout.returncode != 0:
            print(
                f"❌ Failed to checkout branch '{branch_name}':\n{res.stderr or res.stdout}"
            )
            return 1

    print(f"✅ Successfully checked out branch '{branch_name}'.")
    return 0


def cmd_validate_commit(args: argparse.Namespace) -> int:
    """Validate a commit message string or file."""
    msg: str = ""
    if args.message:
        msg = args.message
    elif args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"❌ Commit message file not found: {file_path}")
            return 1
        msg = file_path.read_text(encoding="utf-8", errors="replace")
    elif args.commit_msg_file:
        file_path = Path(args.commit_msg_file)
        if not file_path.exists():
            print(f"❌ Commit message file not found: {file_path}")
            return 1
        msg = file_path.read_text(encoding="utf-8", errors="replace")
    else:
        print("❌ No commit message or file specified for validation.")
        return 1

    valid, errors = validate_commit_message(msg)
    if not valid:
        print("\n❌ Commit message validation failed:")
        for err in errors:
            print(f"  • {err}")
        print("\nSee CONTRIBUTING.md for Conventional Commits standards.\n")
        return 1

    if not getattr(args, "quiet", False):
        print("✅ Commit message is valid under Conventional Commits v1.0.0.")
    return 0


def cmd_commit(args: argparse.Namespace) -> int:
    """Validate commit message, verify licenses, and invoke git commit."""
    repo_root = find_repo_root()
    git_bin = get_git_executable()

    # Pre-commit gate 1: Verify license headers on unstaged/staged python files
    patch_license_script = repo_root / "scripts" / "patch_license.py"
    if patch_license_script.exists():
        run_cmd([sys.executable, str(patch_license_script)], cwd=repo_root)

    # Pre-commit gate 2: Validate commit message if provided via -m
    if args.message:
        valid, errors = validate_commit_message(args.message)
        if not valid:
            print("\n❌ Aborting commit: Commit message does not meet standards:")
            for err in errors:
                print(f"  • {err}")
            return 1

    # Build git commit command
    commit_args = [git_bin, "commit"]
    if args.message:
        commit_args.extend(["-m", args.message])
    if getattr(args, "all", False):
        commit_args.append("-a")
    if getattr(args, "allow_empty", False):
        commit_args.append("--allow-empty")
    if getattr(args, "no_verify", False):
        commit_args.append("--no-verify")

    res = run_cmd(commit_args, cwd=repo_root, capture_output=False)
    return res.returncode


def cmd_check(args: argparse.Namespace) -> int:
    """Run pre-commit architectural verification gates."""
    repo_root = find_repo_root()
    print("🛡️  Running CAGE Pre-Commit Verification Suite...\n")

    checks: list[tuple[str, list[str], bool]] = [
        # (Name, Command, Fail-Closed Required)
        (
            "License Headers (patch_license.py)",
            [sys.executable, "scripts/patch_license.py"],
            True,
        ),
        (
            "Gate G3: Import Boundaries (check_import_boundaries.py)",
            [sys.executable, "scripts/check_import_boundaries.py"],
            True,
        ),
        (
            "STPA Freshness (check_stpa_freshness.py)",
            [sys.executable, "scripts/check_stpa_freshness.py"],
            True,
        ),
        (
            "Gate G9: Doc References (check_doc_references.py)",
            [sys.executable, "scripts/check_doc_references.py"],
            True,
        ),
        (
            "Gate G6: Domain Literals (check_domain_literals.py)",
            [sys.executable, "scripts/check_domain_literals.py"],
            False,
        ),
        (
            "Gate G8: Vendor Brands (check_vendor_brands.py)",
            [sys.executable, "scripts/check_vendor_brands.py"],
            False,
        ),
        (
            "Model-Free Install Gate (check_model_free_install.py)",
            [sys.executable, "scripts/check_model_free_install.py"],
            False,
        ),
        (
            "Conformance Sync Gate (check_conformance_sync.py)",
            [sys.executable, "scripts/check_conformance_sync.py"],
            True,
        ),
        (
            "Lula AI 600-1 Manifest Gate (check_ai600_lula_manifests.py)",
            [sys.executable, "scripts/check_ai600_lula_manifests.py"],
            False,
        ),
    ]

    # Additional gates for --all
    if getattr(args, "all", False) and not getattr(args, "fast", False):
        uv_bin = shutil.which("uv")
        if uv_bin:
            checks.append(
                (
                    "Bandit SAST Security Scan",
                    [
                        uv_bin,
                        "run",
                        "--with",
                        "bandit",
                        "bandit",
                        "-r",
                        "src/",
                        "scripts/",
                        "-c",
                        "pyproject.toml",
                        "-ll",
                        "-ii",
                    ],
                    True,
                )
            )
            checks.append(
                (
                    "Pytest Local Unit Suite",
                    [
                        uv_bin,
                        "run",
                        "pytest",
                        "tests/",
                        "-m",
                        "local or unit",
                        "-p",
                        "no:langsmith",
                        "-q",
                    ],
                    True,
                )
            )
        else:
            checks.append(
                (
                    "Pytest Local Unit Suite",
                    [
                        sys.executable,
                        "-m",
                        "pytest",
                        "tests/",
                        "-m",
                        "local or unit",
                        "-q",
                    ],
                    True,
                )
            )

    # Optional raptor check
    if getattr(args, "raptor", False):
        raptor_env = os.environ.get("CAGE_RAPTOR_SCRIPT", "").strip()
        raptor_bin = shutil.which("raptor")
        if raptor_env and Path(raptor_env).exists():
            checks.append(
                (
                    "RAPTOR Security Audit",
                    [
                        "powershell",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        raptor_env,
                        "-Mode",
                        "all",
                    ],
                    True,
                )
            )
        elif raptor_bin:
            checks.append(
                (
                    "RAPTOR Security Audit",
                    [raptor_bin, "scan", "--repo", str(repo_root)],
                    True,
                )
            )
        else:
            print(
                "  ⚠️ RAPTOR CLI/script not configured (set CAGE_RAPTOR_SCRIPT or install raptor); skipping."
            )

    overall_success = True
    for name, cmd, is_required in checks:
        # Check if target script exists if first arg after python
        if (
            len(cmd) > 1
            and cmd[1].startswith("scripts/")
            and not (repo_root / cmd[1]).exists()
        ):
            continue

        print(f"⏳ Running {name}...")
        res = run_cmd(cmd, cwd=repo_root)
        if res.returncode == 0:
            print(f"  ✅ {name} passed.")
        else:
            print(f"  ❌ {name} failed with exit code {res.returncode}:")
            if res.stdout:
                for line in res.stdout.strip().splitlines()[:10]:
                    print(f"     {line}")
            if res.stderr:
                for line in res.stderr.strip().splitlines()[:10]:
                    print(f"     {line}")
            if is_required:
                overall_success = False

    if overall_success:
        print("\n✨ All pre-commit verification checks passed cleanly!")
        return 0
    else:
        print(
            "\n❌ One or more required architectural gates failed. Please fix before submitting."
        )
        return 1


def cmd_cloudbuild(args: argparse.Namespace) -> int:
    """Submit or dry-run immutable Cloud Build container image jobs."""
    repo_root = find_repo_root()
    image_name = args.image or "gateway"
    env_posture = args.env or "staging"
    project_id = args.project or os.environ.get("PROJECT_ID", "<PROJECT_ID>")

    short_sha = get_short_sha(repo_root)
    if short_sha == "UNKNOWN":
        print(
            "❌ Error: Refusing to build outside a valid git checkout (immutable SHA tag required)."
        )
        return 1

    dockerfile = args.dockerfile
    if not dockerfile:
        # Map well-known service names to Dockerfile paths
        mapping = {
            "gateway": "src/gateway/Dockerfile",
            "agentsight-ui": "src/agentsight-ui/Dockerfile",
            "compliance-bridge": "src/compliance_bridge/Dockerfile",
            "governed-financial-advisor": "Dockerfile",
            "nemo-guardrails": "deployment/docker/Dockerfile.nemo",
            "vllm-streamer": "deployment/docker/Dockerfile.vllm",
            "lula": "deployment/docker/Dockerfile.lula",
        }
        dockerfile = mapping.get(image_name, f"src/{image_name}/Dockerfile")

    config_template = "deployment/docker/cloudbuild.image.yaml"
    if image_name == "vllm-streamer":
        config_template = "deployment/docker/cloudbuild.vllm.yaml"
    elif image_name == "lula":
        config_template = "deployment/docker/cloudbuild.lula.yaml"

    sa_email = f"cage-cloudbuild-{env_posture}@{project_id}.iam.gserviceaccount.com"
    substitutions = (
        f"_IMAGE_NAME={image_name},"
        f"_DOCKERFILE={dockerfile},"
        f"_SHORT_SHA={short_sha},"
        f"_ENVIRONMENT={env_posture}"
    )

    cmd = [
        "gcloud",
        "builds",
        "submit",
        f"--config={config_template}",
        f"--project={project_id}",
        f"--service-account=projects/{project_id}/serviceAccounts/{sa_email}",
        f"--substitutions={substitutions}",
        ".",
    ]

    print("\n🚀 CAGE Immutable Cloud Build Submitter")
    print(f"  • Service Image:  {image_name}")
    print(f"  • Immutable Tag:  :{short_sha}")
    print(f"  • Environment:    {env_posture}")
    print(f"  • Dedicated SA:   {sa_email}")
    print(f"  • Config:         {config_template}\n")

    if args.dry_run:
        print("Dry run requested. Exact command:")
        print(" " + " ".join(cmd))
        return 0

    gcloud_bin = shutil.which("gcloud")
    if not gcloud_bin:
        print(
            "❌ 'gcloud' CLI not found on PATH. Run with --dry-run or install Google Cloud SDK."
        )
        return 1

    res = run_cmd(cmd, cwd=repo_root, capture_output=False)
    return res.returncode


def cmd_verify_service_sync(args: argparse.Namespace) -> int:
    """Verify first-party service catalogue synchronization across scripts and Terraform."""
    repo_root = find_repo_root()
    build_script = repo_root / "scripts" / "build_images.sh"
    render_script = repo_root / "scripts" / "render_image_digests.sh"
    main_tf = repo_root / "infra" / "targets" / "gcp-gke" / "main.tf"
    fixture_tfvars = (
        repo_root
        / "infra"
        / "targets"
        / "gcp-gke"
        / "tests"
        / "fixtures"
        / "image_digests.tfvars"
    )

    required_files = [
        ("build_images.sh", build_script),
        ("render_image_digests.sh", render_script),
        ("main.tf", main_tf),
        ("image_digests.tfvars", fixture_tfvars),
    ]
    missing_files = [name for name, path in required_files if not path.is_file()]
    if missing_files:
        print(f"❌ Missing required catalogue file(s): {', '.join(missing_files)}")
        return 1

    errors: list[str] = []

    def extract_bash_array(path: Path, var_name: str) -> list[str]:
        if not path.is_file():
            return []
        text = path.read_text(encoding="utf-8")
        m = re.search(rf"^{var_name}=\((.*?)\)", text, re.M | re.S)
        if not m:
            return []
        return [item.split("|")[0] for item in re.findall(r'"([^"]+)"', m.group(1))]

    # 1. Parse build_images.sh ALL_IMAGES
    all_images_match = re.search(
        r'^ALL_IMAGES="([^"]+)"',
        build_script.read_text(encoding="utf-8") if build_script.is_file() else "",
        re.M,
    )
    all_images = set(all_images_match.group(1).split()) if all_images_match else set()

    # 2. Parse render_image_digests.sh FIRST_PARTY_IMAGES and THIRD_PARTY_TAGGED_IMAGES
    render_first_party = set(extract_bash_array(render_script, "FIRST_PARTY_IMAGES"))
    render_third_party = set(
        extract_bash_array(render_script, "THIRD_PARTY_TAGGED_IMAGES")
    )
    catalogue = render_first_party | render_third_party

    # 3. Parse main.tf required_image_digests
    tf_images: set[str] = set()
    if main_tf.is_file():
        text = main_tf.read_text(encoding="utf-8")
        m = re.search(r"required_image_digests\s*=\s*concat\((.*?)\n\s*\)", text, re.S)
        if m:
            tf_images = set(re.findall(r'"([a-z0-9-]+)"', m.group(1)))

    # 4. Parse fixture tfvars
    fixture_images: set[str] = set()
    if fixture_tfvars.is_file():
        text = fixture_tfvars.read_text(encoding="utf-8")
        fixture_images = set(re.findall(r'^\s*"([^"]+)"\s*=', text, re.M))

    print("🔍 Checking Service Catalogue Agreement...")

    # Check builder and renderer know the same first party images
    if all_images != render_first_party:
        errors.append(
            f"build_images.sh ALL_IMAGES {sorted(all_images)} != "
            f"render_image_digests.sh FIRST_PARTY_IMAGES {sorted(render_first_party)}"
        )

    # Check renderer can render every image terraform can require
    missing_from_catalogue = tf_images - catalogue
    if missing_from_catalogue:
        errors.append(
            f"render_image_digests.sh catalogue missing images required by main.tf: {sorted(missing_from_catalogue)}"
        )

    # Check fixture covers every required image
    missing_from_fixture = tf_images - fixture_images
    if missing_from_fixture:
        errors.append(
            f"image_digests.tfvars fixture missing entries for required images: {sorted(missing_from_fixture)}"
        )

    if errors:
        print("\n❌ Service catalogue synchronization drift detected:")
        for err in errors:
            print(f"  • {err}")
        return 1

    print(
        "✅ Service catalogues across build_images.sh, render_image_digests.sh, and Terraform are fully in sync!"
    )
    return 0


def cmd_scaffold(args: argparse.Namespace) -> int:
    """Scaffold ADR-009 tiers, Layer 3 seams, or domain plugins."""
    repo_root = find_repo_root()
    scaffold_type = args.scaffold_type

    if scaffold_type == "tier":
        domain = args.domain.lower().replace("-", "_")
        tier_name = args.name.lower().replace("-", "_")
        phase = int(args.phase or 1)
        order = int(args.order or 10)

        domain_dir = repo_root / f"src/cage_{domain}/tiers"
        domain_dir.mkdir(parents=True, exist_ok=True)
        tier_file = domain_dir / f"{tier_name}_tier.py"

        class_name = "".join(w.capitalize() for w in tier_name.split("_")) + "Tier"

        if phase == 1:
            tier_code = f"""{APACHE_LICENSE_HEADER}
\"\"\"ADR-009 Phase 1 Read-Only Governance Tier: {class_name}.\"\"\"

from __future__ import annotations

from typing import Any

from src.gateway.governance.contracts import ReadOnlyTier, Violation, ViolationKind


class {class_name}(ReadOnlyTier):
    \"\"\"Phase 1 Read-Only governance tier. Strictly side-effect free.\"\"\"

    @property
    def tier_name(self) -> str:
        return "{tier_name}"

    @property
    def order(self) -> int:
        return {order}

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        violations: list[Violation] = []
        return violations
"""
        else:
            tier_code = f"""{APACHE_LICENSE_HEADER}
\"\"\"ADR-009 Phase 2 Mutating Governance Tier: {class_name}.\"\"\"

from __future__ import annotations

from typing import Any

from src.gateway.governance.contracts import CommitReceipt, MutatingTier, Violation


class {class_name}(MutatingTier):
    \"\"\"Phase 2 Mutating governance tier. Reserves and settles state.\"\"\"

    @property
    def tier_name(self) -> str:
        return "{tier_name}"

    @property
    def order(self) -> int:
        return {order}

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return True

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        return []

    async def commit(
        self, action: str, params: dict[str, Any]
    ) -> tuple[list[Violation], CommitReceipt | None]:
        return [], CommitReceipt(tier=self.tier_name, token="{tier_name}-reservation-001")

    async def rollback(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        pass

    async def confirm(
        self, action: str, params: dict[str, Any], receipt: CommitReceipt
    ) -> None:
        pass
"""
        tier_file.write_text(tier_code, encoding="utf-8")
        print(
            f"✅ Scaffolded Phase {phase} tier at: {tier_file.relative_to(repo_root)}"
        )

    elif scaffold_type == "seam":
        seam_type = args.seam_type.lower()
        seam_name = args.name.lower()
        pkg_dir = repo_root / f"src/integrations/{seam_name}"
        pkg_dir.mkdir(parents=True, exist_ok=True)

        init_file = pkg_dir / "__init__.py"
        init_file.write_text(
            f'{APACHE_LICENSE_HEADER}\n"""Integration adapter for {seam_name}."""\n',
            encoding="utf-8",
        )

        adapter_file = pkg_dir / "adapter.py"
        adapter_code = f"""{APACHE_LICENSE_HEADER}
\"\"\"Anonymized Layer 3 Seam Adapter: {seam_name}.\"\"\"

from __future__ import annotations

from typing import Any
"""
        if seam_type == "normative":
            adapter_code += """
from src.gateway.governance.seams.normative import (
    EvidenceSeal,
    NormativeBaseline,
    NormativeProvider,
    ValidationResult,
)


class NormativeAdapter(NormativeProvider):
    async def fetch_baseline(self, region: str) -> NormativeBaseline:
        return NormativeBaseline(region=region, profile={})

    async def validate_fria(self, payload: dict[str, Any]) -> ValidationResult:
        return ValidationResult(admitted=True, findings=[])

    async def submit_evidence(self, thread_id: str, evidence_hash: str) -> EvidenceSeal:
        return EvidenceSeal(thread_id=thread_id, seal_hash="SEAL_HASH_PLACEHOLDER")
"""
        elif seam_type == "actuator":
            adapter_code += """
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ActuationReceipt,
    ExecutionActuator,
    ExecutionClearance,
    ActuatorCapability,
)


class ActuatorAdapter(ExecutionActuator):
    @property
    def actuator_id(self) -> str:
        return "__SEAM_NAME__"

    async def health_check(self) -> bool:
        return True

    def get_capabilities(self) -> set[ActuatorCapability]:
        return {ActuatorCapability.SIGNED_RECEIPTS}

    async def actuate(self, clearance: ExecutionClearance) -> ActuationReceipt:
        return ActuationReceipt(
            accepted=True,
            receipt_id="RECEIPT_001",
            session_uuid=None,
            raw_receipt={},
            outcome=ActuationOutcome.ACCEPTED,
        )
""".replace("__SEAM_NAME__", seam_name)
        elif seam_type == "quarantine":
            adapter_code += """
from src.gateway.governance.seams.actuation import ActuationOutcome
from src.gateway.governance.seams.quarantine import (
    QuarantineActuator,
    QuarantineDirective,
    QuarantineReceipt,
)


class QuarantineAdapter(QuarantineActuator):
    @property
    def actuator_id(self) -> str:
        return "__SEAM_NAME__"

    async def health_check(self) -> bool:
        return True

    async def quarantine_workload(
        self, directive: QuarantineDirective
    ) -> QuarantineReceipt:
        rule_id = (
            directive.violation_codes[0]
            if directive.violation_codes
            else directive.reason.value
        )
        return QuarantineReceipt(
            quarantined=True,
            enforcement_plane="SIMULATED",
            rule_id=rule_id,
            latency_us=100.0,
            outcome=ActuationOutcome.ACCEPTED,
        )
""".replace("__SEAM_NAME__", seam_name)
        elif seam_type == "attestation":
            adapter_code += """
from src.gateway.governance.seams.attestation import (
    AttestationProvider,
    AttestationStatus,
    ExternalAttestation,
)


class AttestationAdapter(AttestationProvider):
    @property
    def provider_name(self) -> str:
        return "__SEAM_NAME__"

    async def fetch_attestations(
        self, context: dict[str, Any]
    ) -> list[ExternalAttestation]:
        return []
""".replace("__SEAM_NAME__", seam_name)
        elif seam_type == "evidence":
            adapter_code += """
from src.gateway.governance.seams.evidence import (
    EvidenceCollector,
    EvidenceReceipt,
    EvidenceRecord,
)


class EvidenceAdapter(EvidenceCollector):
    @property
    def collector_name(self) -> str:
        return "__SEAM_NAME__"

    async def collect_evidence(self, record: EvidenceRecord) -> EvidenceReceipt:
        return EvidenceReceipt(
            receipt_id="EVID_001",
            stored=True,
            stream_offset=0,
            receipt_sha256="EVIDENCE_SHA256_PLACEHOLDER",
        )

    async def flush_batch(self, batch_id: str) -> EvidenceReceipt:
        return EvidenceReceipt(
            receipt_id=f"BATCH_{batch_id}",
            stored=True,
            stream_offset=0,
            receipt_sha256="BATCH_SHA256_PLACEHOLDER",
        )
""".replace("__SEAM_NAME__", seam_name)

        adapter_file.write_text(adapter_code, encoding="utf-8")
        readme_file = pkg_dir / "README.md"
        readme_file.write_text(
            f"# {seam_name}\n\nLayer 3 {seam_type} seam adapter.\n", encoding="utf-8"
        )
        print(f"✅ Scaffolded {seam_type} seam at: {pkg_dir.relative_to(repo_root)}")

    return 0


def cmd_pr(args: argparse.Namespace) -> int:
    """Validate branch readiness, clean tree, squash-merge guard, and open PR."""
    repo_root = find_repo_root()
    git_bin = get_git_executable()

    curr_branch = get_current_branch(repo_root)
    valid, reason = validate_branch_name(curr_branch)
    if not valid:
        print(
            f"\n❌ Cannot open PR from invalid branch '{curr_branch}':\n   {reason}\n"
        )
        return 1

    if not getattr(args, "allow_dirty", False) and not is_working_tree_clean(repo_root):
        print(
            "\n❌ Working tree has uncommitted changes. Commit or stash them before creating a PR.\n"
        )
        return 1

    base_branch = args.base or "main"
    # Squash-merge guard check: verify zero two-parent merge commits between base and HEAD
    res_parents = run_cmd(
        [git_bin, "rev-list", "--parents", f"{base_branch}..HEAD"], cwd=repo_root
    )
    if res_parents.returncode == 0:
        for line in res_parents.stdout.strip().splitlines():
            parts = line.strip().split()
            if len(parts) > 2:
                print(
                    f"\n❌ Squash-Merge Guard Violation: Found two-parent merge commit: {parts[0]}"
                )
                print(
                    "   Merge commits on feature branches are strictly forbidden. Rebase or squash instead."
                )
                return 1

    title = args.title or ""
    if not title:
        # Generate default title from last commit
        res_last = run_cmd([git_bin, "log", "-1", "--pretty=%s"], cwd=repo_root)
        if res_last.returncode == 0:
            title = res_last.stdout.strip()

    valid_title, title_errors = validate_commit_message(title)
    if not valid_title:
        print(f"\n❌ PR Title '{title}' does not follow Conventional Commits:")
        for err in title_errors:
            print(f"  • {err}")
        return 1

    body = args.body or "Automated Pull Request via cage_contribute.py"

    print(f"🚀 Pushing branch '{curr_branch}' to origin...")
    if args.dry_run:
        print(f"  [Dry Run] git push -u origin {curr_branch}")
        print(
            f'  [Dry Run] gh pr create --base {base_branch} --head {curr_branch} --title "{title}" --body "{body}"'
        )
        return 0

    run_cmd(
        [git_bin, "push", "-u", "origin", curr_branch],
        cwd=repo_root,
        capture_output=False,
    )

    gh_bin = shutil.which("gh")
    if gh_bin:
        res_gh = run_cmd(
            [
                gh_bin,
                "pr",
                "create",
                "--base",
                base_branch,
                "--head",
                curr_branch,
                "--title",
                title,
                "--body",
                body,
            ],
            cwd=repo_root,
            capture_output=False,
        )
        return res_gh.returncode
    else:
        print(
            "\n[INFO] Branch pushed. 'gh' CLI not found; open pull request in browser or install gh."
        )
        return 0


def cmd_release_tag(args: argparse.Namespace) -> int:
    """Validate tag format and CHANGELOG before creating an annotated release tag."""
    repo_root = find_repo_root()
    git_bin = get_git_executable()
    tag = args.tag

    tag_regex = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9.-]+)?$")
    if not tag_regex.match(tag):
        print(
            f"❌ Invalid release tag format: '{tag}'. Expected 'v<MAJOR>.<MINOR>.<PATCH>[-<pre-release>]'."
        )
        return 1

    # Verify CHANGELOG contains tag
    changelog_path = repo_root / "CHANGELOG.md"
    if changelog_path.exists():
        text = changelog_path.read_text(encoding="utf-8")
        clean_ver = tag.lstrip("v")
        if tag not in text and clean_ver not in text:
            print(
                f"❌ CHANGELOG.md does not contain release entry for version '{tag}' ({clean_ver})."
            )
            print("   Update CHANGELOG.md before tagging the release.")
            return 1
    else:
        print("⚠️ CHANGELOG.md not found in repository root.")

    print(f"🏷️ Creating annotated release tag: {tag}...")
    msg = f"release: {tag} — Cybernetic Governance Engine"
    res = run_cmd([git_bin, "tag", "-a", tag, "-m", msg], cwd=repo_root)
    if res.returncode != 0:
        print(f"❌ Failed to create tag:\n{res.stderr or res.stdout}")
        return 1

    print(f"✅ Annotated tag '{tag}' created successfully!")
    print(f"   Push to remote with: git push origin {tag}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Diagnose contributor environment and toolchain health."""
    repo_root = find_repo_root()
    git_bin = get_git_executable()

    print("🩺 Cybernetic Agent Governance Engine — Environment Doctor\n")

    # 1. Git
    git_ver = "Unknown"
    git_valid = False
    try:
        git_res = run_cmd([git_bin, "--version"])
        if git_res.returncode == 0:
            git_ver = git_res.stdout.strip()
            git_valid = True
        else:
            git_ver = f"Error executing git (exit code {git_res.returncode})"
    except (FileNotFoundError, OSError):
        git_ver = "Not found"

    if git_valid:
        branch = get_current_branch(repo_root)
        valid_branch, _ = validate_branch_name(branch)
        branch_icon = (
            "✅" if valid_branch else ("⚠️" if branch in PROTECTED_BRANCHES else "❌")
        )
        print(f"  • Git Executable:   {git_bin}")
        print(f"  • Git Version:      {git_ver}")
        print(f"  • Current Branch:   {branch_icon} {branch}")
        print(
            f"  • Working Tree:     {'✅ Clean' if is_working_tree_clean(repo_root) else '⚠️ Uncommitted changes'}"
        )
    else:
        print(f"  • Git Executable:   ❌ Not found ({git_bin})")
        print(f"  • Git Version:      ❌ {git_ver}")
        print("  • Current Branch:   ⚠️  Unknown")
        print("  • Working Tree:     ⚠️  Unknown")

    # 2. Python
    py_ver = platform.python_version()
    py_valid = sys.version_info >= (3, 10)
    print(
        f"  • Python Version:   {'✅' if py_valid else '❌'} {py_ver} ({sys.executable})"
    )

    # 3. uv
    uv_bin = shutil.which("uv")
    if uv_bin:
        try:
            uv_ver = run_cmd([uv_bin, "--version"]).stdout.strip()
            print(f"  • uv Package Mgr:   ✅ {uv_ver}")
        except (FileNotFoundError, OSError):
            print("  • uv Package Mgr:   ⚠️  CLI found, but not executable")
    else:
        print(
            "  • uv Package Mgr:   ⚠️  Not installed (install via https://astral.sh/uv/)"
        )

    # 4. Node & npm
    node_bin = shutil.which("node")
    npm_bin = shutil.which("npm")
    if node_bin and npm_bin:
        try:
            node_ver = run_cmd([node_bin, "--version"]).stdout.strip()
            print(f"  • Node.js & npm:    ✅ Node {node_ver}")
        except (FileNotFoundError, OSError):
            print("  • Node.js & npm:    ⚠️  CLI found, but not executable")
    else:
        print(
            "  • Node.js & npm:    ⚠️  Not installed (required for src/agentsight-ui/)"
        )

    # 5. Docker
    docker_bin = shutil.which("docker")
    if docker_bin:
        try:
            docker_info = run_cmd(
                [docker_bin, "info", "--format", "{{.ServerVersion}}"]
            )
            if docker_info.returncode == 0:
                print(
                    f"  • Docker Daemon:    ✅ Running (Engine {docker_info.stdout.strip()})"
                )
            else:
                print(
                    "  • Docker Daemon:    ⚠️  CLI found, but daemon is not responding"
                )
        except (FileNotFoundError, OSError):
            print("  • Docker Daemon:    ⚠️  Docker CLI found, but not executable")
    else:
        print("  • Docker Daemon:    ⚠️  Docker CLI not found")

    # 6. gcloud
    gcloud_bin = shutil.which("gcloud")
    if gcloud_bin:
        try:
            proj = run_cmd(
                [gcloud_bin, "config", "get-value", "project"]
            ).stdout.strip()
            print(
                f"  • Google Cloud SDK: ✅ Installed (active project: {proj or 'none'})"
            )
        except (FileNotFoundError, OSError):
            print("  • Google Cloud SDK: ⚠️  gcloud CLI found, but not executable")
    else:
        print(
            "  • Google Cloud SDK: [INFO] Not installed (needed for Cloud Build submissions)"
        )

    # 7. Git Hooks
    hooks_dir = get_git_hooks_dir(repo_root)
    hooks_installed = (hooks_dir / "commit-msg").exists() and (
        hooks_dir / "pre-push"
    ).exists()
    print(
        f"  • CAGE Git Hooks:   {'✅ Installed' if hooks_installed else '❌ Missing (run: python scripts/cage_contribute.py setup)'}"
    )

    if not py_valid or not hooks_installed or not git_valid:
        print("\n❌ One or more critical environment checks failed.")
        return 1

    print("\n✨ Diagnostic check completed.")
    return 0


# ---------------------------------------------------------------------------
# CLI Argument Parser Construction
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser and subcommands."""
    parser = argparse.ArgumentParser(
        prog="cage_contribute.py",
        description="Google-standard contributor automation CLI for Cybernetic Governance Engine.",
    )
    subparsers = parser.add_subparsers(
        dest="subcommand", required=True, help="Available subcommands"
    )

    # setup
    p_setup = subparsers.add_parser(
        "setup", help="Configure git hooks, commit template, and .env"
    )
    p_setup.add_argument(
        "--sync", action="store_true", help="Run 'uv sync --all-groups --all-extras'"
    )
    p_setup.set_defaults(func=cmd_setup)

    # branch
    p_branch = subparsers.add_parser(
        "branch", help="Validate and checkout a CAGE feature branch"
    )
    p_branch.add_argument(
        "type", help="Branch type (feat, fix, docs, refactor, etc.) or full branch name"
    )
    p_branch.add_argument(
        "description",
        nargs="?",
        default="",
        help="Kebab-case description (<= 30 chars)",
    )
    p_branch.add_argument("--base", default="main", help="Base branch (default: main)")
    p_branch.set_defaults(func=cmd_branch)

    # validate-commit
    p_val_commit = subparsers.add_parser(
        "validate-commit", help="Validate a Conventional Commits message"
    )
    p_val_commit.add_argument(
        "commit_msg_file", nargs="?", help="Path to commit message file (from git hook)"
    )
    p_val_commit.add_argument(
        "-m", "--message", help="Commit message string to validate"
    )
    p_val_commit.add_argument("-F", "--file", help="File containing commit message")
    p_val_commit.add_argument(
        "-q", "--quiet", action="store_true", help="Quiet output on success"
    )
    p_val_commit.set_defaults(func=cmd_validate_commit)

    # commit
    p_commit = subparsers.add_parser(
        "commit", help="Validate commit message and invoke git commit"
    )
    p_commit.add_argument("-m", "--message", help="Commit message")
    p_commit.add_argument(
        "-a", "--all", action="store_true", help="Stage all modified files"
    )
    p_commit.add_argument(
        "--allow-empty", action="store_true", help="Allow empty commit"
    )
    p_commit.add_argument("--no-verify", action="store_true", help="Bypass git hooks")
    p_commit.set_defaults(func=cmd_commit)

    # check
    p_check = subparsers.add_parser(
        "check", help="Run pre-commit architectural verification gates"
    )
    p_check.add_argument(
        "--fast",
        action="store_true",
        help="Run fast static gates only (skip bandit & pytest)",
    )
    p_check.add_argument(
        "--all", action="store_true", help="Run full suite including SAST and tests"
    )
    p_check.add_argument(
        "--raptor", action="store_true", help="Run RAPTOR security scanner"
    )
    p_check.add_argument(
        "--security-audit", action="store_true", help="Validate security audit ledger"
    )
    p_check.set_defaults(func=cmd_check)

    # cloudbuild
    p_cb = subparsers.add_parser(
        "cloudbuild",
        help="Submit or dry-run immutable Cloud Build container image jobs",
    )
    p_cb.add_argument(
        "--image",
        default="gateway",
        help="Image name (gateway, compliance-bridge, etc.)",
    )
    p_cb.add_argument("--dockerfile", help="Path to Dockerfile (inferred if omitted)")
    p_cb.add_argument(
        "--env", default="staging", help="Target environment posture (default: staging)"
    )
    p_cb.add_argument("--project", help="GCP project ID (or PROJECT_ID env)")
    p_cb.add_argument(
        "--dry-run", action="store_true", help="Print command without executing"
    )
    p_cb.set_defaults(func=cmd_cloudbuild)

    # verify-service-sync
    p_sync = subparsers.add_parser(
        "verify-service-sync", help="Verify service catalogue agreement across repo"
    )
    p_sync.set_defaults(func=cmd_verify_service_sync)

    # scaffold
    p_scaffold = subparsers.add_parser(
        "scaffold", help="Scaffold ADR-009 tiers, Layer 3 seams, or domain plugins"
    )
    scaffold_sub = p_scaffold.add_subparsers(dest="scaffold_type", required=True)

    # scaffold tier
    p_sc_tier = scaffold_sub.add_parser("tier", help="Scaffold ADR-009 governance tier")
    p_sc_tier.add_argument(
        "domain", help="Target domain (finance, healthcare, physical_ai)"
    )
    p_sc_tier.add_argument("name", help="Tier name (e.g. trade_risk, dosage_limit)")
    p_sc_tier.add_argument(
        "--phase",
        type=int,
        choices=[1, 2],
        default=1,
        help="Phase 1 (ReadOnly) or 2 (Mutating)",
    )
    p_sc_tier.add_argument(
        "--order", type=int, default=10, help="Explicit tier evaluation order"
    )

    # scaffold seam
    p_sc_seam = scaffold_sub.add_parser(
        "seam", help="Scaffold Layer 3 integration seam"
    )
    p_sc_seam.add_argument(
        "seam_type",
        choices=["normative", "attestation", "actuator", "quarantine", "evidence"],
        help="Seam protocol type",
    )
    p_sc_seam.add_argument(
        "name", help="Anonymized package name (e.g. provider_07, actuator_05)"
    )

    p_scaffold.set_defaults(func=cmd_scaffold)

    # pr
    p_pr = subparsers.add_parser(
        "pr",
        help="Validate branch readiness, clean tree, squash-merge guard, and open PR",
    )
    p_pr.add_argument("--title", help="PR title (must follow Conventional Commits)")
    p_pr.add_argument("--body", help="PR description body")
    p_pr.add_argument("--base", default="main", help="Base branch (default: main)")
    p_pr.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow PR creation with unstaged changes",
    )
    p_pr.add_argument(
        "--dry-run", action="store_true", help="Print commands without executing"
    )
    p_pr.set_defaults(func=cmd_pr)

    # release-tag
    p_tag = subparsers.add_parser(
        "release-tag", help="Validate tag and CHANGELOG before creating release tag"
    )
    p_tag.add_argument("tag", help="Annotated release tag (e.g. v3.2.0)")
    p_tag.set_defaults(func=cmd_release_tag)

    # doctor
    p_doc = subparsers.add_parser(
        "doctor", help="Diagnose contributor environment and toolchain health"
    )
    p_doc.set_defaults(func=cmd_doctor)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for cage_contribute CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if hasattr(args, "func"):
        return args.func(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
