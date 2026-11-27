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

"""check_project_id_hygiene.py — Project-ID Hygiene Gate

Scans tracked repository files to ensure no maintainer-specific cloud project
identifiers (e.g. 'laah-cybernetics') are embedded in active code, templates,
manifests, or documentation.

Historical measurement records under docs/paper/measurements/2026-*/ and
historical planning documents under plans/ are excluded to preserve provenance.

Tracked Terraform state (``*.tfstate`` and ``*.tfstate.*`` backups) is always a
violation, wherever it lives: state files carry provisioned credentials
(POAM-2026-071), so ``.gitignore`` keeping them untracked is enforced here.

Exit code 0 on clean scan, 1 on violation.
"""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

PROHIBITED_IDENTIFIERS = [
    "laah-cybernetics",
]

EXCLUDED_PATH_PREFIXES = (
    "docs/paper/measurements/2026-",
    "plans/",
    "scripts/check_project_id_hygiene.py",
)

_SHELL_SEPARATORS = frozenset({";", "&&", "||", "|"})
_PATH_FLAGS = frozenset({"--body-file", "--input"})
_AT_VALUE_FLAGS = frozenset({"-F", "--field", "--raw-field"})


def get_tracked_files(repo_root: Path | None = None) -> list[str]:
    """Return all git-tracked files using NUL-delimited ``git ls-files -z``."""
    root = Path(".") if repo_root is None else repo_root
    try:
        out = subprocess.check_output(
            ["git", "ls-files", "-z"],
            cwd=root,
            stderr=subprocess.DEVNULL,
        )
        return [
            entry.decode("utf-8", errors="surrogateescape")
            for entry in out.split(b"\x00")
            if entry
        ]
    except subprocess.CalledProcessError:
        return [
            p.relative_to(root).as_posix()
            for p in root.rglob("*")
            if p.is_file() and ".git" not in p.relative_to(root).parts
        ]


def is_terraform_state_path(rel_path: str) -> bool:
    """Return True for Terraform state files and their backups (``*.tfstate`` / ``*.tfstate.*backup``)."""
    name = Path(rel_path).name
    if name.endswith((".tfstate", ".tfstate.backup", ".tfstate.lock.info")):
        return True
    stem, sep, tail = name.partition(".tfstate.")
    return bool(
        sep
        and stem
        and all(
            part.isdigit() or part in {"backup", "bak", "tmp"}
            for part in tail.split(".")
        )
    )


def scan_tracked_files(
    repo_root: Path,
    tracked_files: list[str],
    prohibited_identifiers: Sequence[str] = PROHIBITED_IDENTIFIERS,
) -> list[tuple[str, int, str]]:
    """Return ``(path, line, text)`` for every violation in ``tracked_files``.

    A tracked Terraform state file is reported (line 0) whether or not it exists
    on disk, since being tracked is the violation. Every other file outside
    ``EXCLUDED_PATH_PREFIXES`` is scanned line by line for the identifiers.
    """
    violations: list[tuple[str, int, str]] = []
    for rel_path in tracked_files:
        if is_terraform_state_path(rel_path):
            violations.append(
                (rel_path, 0, "tracked Terraform state file (POAM-2026-071)")
            )
            continue
        if any(rel_path.startswith(prefix) for prefix in EXCLUDED_PATH_PREFIXES):
            continue

        file_path = repo_root / rel_path
        if not file_path.is_file():
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for line_num, line in enumerate(content.splitlines(), start=1):
            for ident in prohibited_identifiers:
                if ident in line:
                    violations.append((rel_path, line_num, line.strip()))
    return violations


def _split_shell_segments(cmdline: str) -> list[list[str]]:
    lexer = shlex.shlex(cmdline, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    segments: list[list[str]] = []
    current: list[str] = []
    for token in lexer:
        if token in _SHELL_SEPARATORS:
            if current:
                segments.append(current)
                current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def _extract_at_path(value: str) -> tuple[str, str] | None:
    if value.startswith("@"):
        return ("@", value[1:])
    if "=@" in value:
        key, _, path = value.partition("=@")
        return (f"{key}=@", path)
    return None


def _is_git_push_segment(tokens: Sequence[str]) -> bool:
    if not tokens or Path(tokens[0]).name != "git":
        return False
    idx = 1
    while idx < len(tokens):
        tok = tokens[idx]
        if tok in {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}:
            idx += 2
            continue
        if tok.startswith("-"):
            idx += 1
            continue
        return tok == "push"
    return False


def _inspect_segment(
    tokens: Sequence[str],
    *,
    cwd: Path,
    prohibited_identifiers: Sequence[str],
    unpushed_commit_count: int | None,
) -> list[str]:
    """Scan command tokens after excising file-payload paths, and scan those files."""
    violations: list[str] = []
    if unpushed_commit_count == 0 and _is_git_push_segment(tokens):
        violations.append(
            "git push guard refused vacuous 0-commit scan (split commit and push)"
        )

    scrubbed_tokens: list[str] = []
    referenced_paths: list[str] = []
    is_gh = bool(tokens) and Path(tokens[0]).name == "gh"
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if is_gh and tok in _PATH_FLAGS and idx + 1 < len(tokens):
            scrubbed_tokens.append(tok)
            next_val = tokens[idx + 1]
            if next_val == "-":
                scrubbed_tokens.append(next_val)
            else:
                referenced_paths.append(next_val)
            idx += 2
            continue
        if is_gh and any(tok.startswith(f"{flag}=") for flag in _PATH_FLAGS):
            flag_prefix, _, path_val = tok.partition("=")
            if path_val == "-":
                scrubbed_tokens.append(tok)
            else:
                scrubbed_tokens.append(f"{flag_prefix}=")
                referenced_paths.append(path_val)
            idx += 1
            continue
        if is_gh and tok in _AT_VALUE_FLAGS and idx + 1 < len(tokens):
            scrubbed_tokens.append(tok)
            extracted = _extract_at_path(tokens[idx + 1])
            if extracted is not None and extracted[1] != "-":
                scrubbed_tokens.append(extracted[0])
                referenced_paths.append(extracted[1])
            else:
                scrubbed_tokens.append(tokens[idx + 1])
            idx += 2
            continue
        if is_gh and (
            tok.startswith("-F")
            or tok.startswith("--field=")
            or tok.startswith("--raw-field=")
        ):
            prefix, sep, rhs = tok.partition("=")
            if not sep and tok.startswith("-F@"):
                scrubbed_tokens.append("-F@")
                if tok[3:] != "-":
                    referenced_paths.append(tok[3:])
                idx += 1
                continue
            if sep:
                extracted = _extract_at_path(rhs)
                if extracted is not None and extracted[1] != "-":
                    scrubbed_tokens.append(f"{prefix}={extracted[0]}")
                    referenced_paths.append(extracted[1])
                    idx += 1
                    continue
        scrubbed_tokens.append(tok)
        idx += 1

    scrubbed_text = " ".join(scrubbed_tokens)
    for ident in prohibited_identifiers:
        if ident in scrubbed_text:
            violations.append(
                f"command arguments/data contain prohibited identifier {ident!r}"
            )

    for raw_path in referenced_paths:
        resolved = Path(raw_path)
        if not resolved.is_absolute():
            resolved = cwd / resolved
        try:
            payload = resolved.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            violations.append(
                f"referenced payload file {raw_path!r} unreadable (fail closed): {exc}"
            )
            continue
        for ident in prohibited_identifiers:
            if ident in payload:
                violations.append(
                    f"referenced payload {raw_path!r} contains prohibited identifier {ident!r}"
                )
    return violations


def audit_command_payloads(
    cmdline: str,
    *,
    cwd: Path | None = None,
    prohibited_identifiers: Sequence[str] = PROHIBITED_IDENTIFIERS,
    unpushed_commit_count: int | None = None,
) -> list[str]:
    """Audit a shell command line by excising file-payload paths and reading their files.

    Keeps the path-excision list and referenced-payload reader unified so a clean
    payload at a path containing a denylist substring is accepted while leaks in
    referenced files, inline flags, heredocs, or 0-commit ``git push`` calls fail
    closed (POAM-2026-214).
    """
    base_dir = cwd if cwd is not None else Path(".")
    violations: list[str] = []
    try:
        segments = _split_shell_segments(cmdline)
    except ValueError as exc:
        violations.append(f"unparseable shell command line (fail closed): {exc}")
        for ident in prohibited_identifiers:
            if ident in cmdline:
                violations.append(
                    f"raw command line contains prohibited identifier {ident!r}"
                )
        return violations

    for segment in segments:
        violations.extend(
            _inspect_segment(
                segment,
                cwd=base_dir,
                prohibited_identifiers=prohibited_identifiers,
                unpushed_commit_count=unpushed_commit_count,
            )
        )
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check for maintainer project ID leaks"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    tracked_files = get_tracked_files()
    violations = scan_tracked_files(Path("."), tracked_files)

    if violations:
        print(
            f"❌ Project ID hygiene gate FAILED: {len(violations)} violation(s) found:"
        )
        for path, line_num, line in violations:
            print(f"  {path}:{line_num}: {line}")
        return 1

    if args.verbose:
        print(f"✅ Project ID hygiene gate PASSED: scanned {len(tracked_files)} files.")
    else:
        print("✅ Project ID hygiene gate PASSED: no maintainer project IDs detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
