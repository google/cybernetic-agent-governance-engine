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

Exit code 0 on clean scan, 1 on violation.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check for maintainer project ID leaks"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    tracked_files = get_tracked_files()
    violations: list[tuple[str, int, str]] = []

    for rel_path in tracked_files:
        if any(rel_path.startswith(prefix) for prefix in EXCLUDED_PATH_PREFIXES):
            continue

        file_path = Path(rel_path)
        if not file_path.is_file():
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for line_num, line in enumerate(content.splitlines(), start=1):
            for ident in PROHIBITED_IDENTIFIERS:
                if ident in line:
                    violations.append((rel_path, line_num, line.strip()))

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
