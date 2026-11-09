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


def get_tracked_files() -> list[str]:
    """Return all git-tracked files."""
    try:
        out = subprocess.check_output(
            ["git", "ls-files"], text=True, stderr=subprocess.DEVNULL
        )
        return [line.strip() for line in out.splitlines() if line.strip()]
    except subprocess.CalledProcessError:
        root = Path(".")
        return [
            str(p)
            for p in root.rglob("*")
            if p.is_file() and not str(p).startswith(".git")
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
