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

"""
check_stpa_freshness.py — CI staleness guard for generated STPA artifacts
=========================================================================

Fails with exit code 1 if any generated STPA artifact is older than its
source ``config/stpa_control_structure.yaml``, or if the ``Generated:``
timestamp embedded in the artifact pre-dates the source file's last
modification time.

Usage::

    # In CI (fails the build if artifacts are stale)
    python scripts/check_stpa_freshness.py

    # Local check with verbose output
    python scripts/check_stpa_freshness.py --verbose

Exit codes:
    0  All artifacts are current.
    1  One or more artifacts are stale — re-run the compiler:
       python -m src.gateway.governance.stpa_compiler compile
"""

from __future__ import annotations

import argparse
import datetime
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths (relative to repo root)
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[1]

# Multi-source directory — all *.yaml files under config/stpa/ are the authoritative
# STPA sources after the PR 2 split. The legacy config/stpa_control_structure.yaml is
# retained as the Gate 1 drift oracle but is no longer the primary freshness reference.
_SOURCE_DIR = _REPO_ROOT / "config" / "stpa"
# Fallback single-file path for environments that have not yet migrated.
_SOURCE_LEGACY = _REPO_ROOT / "config" / "stpa_control_structure.yaml"

_GENERATED_ARTIFACTS: list[Path] = [
    _REPO_ROOT / "src" / "gateway" / "governance" / "generated_stpa_validator.py",
    _REPO_ROOT / "config" / "opa" / "generated_stpa_policy.rego",
    _REPO_ROOT / "config" / "rails" / "generated_stpa_rails.co",
    _REPO_ROOT / "config" / "agp" / "generated_semantic_policy.txt",  # PR 2: added
]

# Regex that matches the "Generated: <ISO-8601>" comment embedded by the compiler.
_GENERATED_TS_RE = re.compile(
    r"Generated:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)"
)


def _parse_embedded_timestamp(artifact: Path) -> datetime.datetime | None:
    """Extract the ``Generated:`` timestamp from the first 30 lines of *artifact*."""
    try:
        with artifact.open(encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                if i >= 30:
                    break
                m = _GENERATED_TS_RE.search(line)
                if m:
                    ts_str = m.group(1)
                    # Normalise timezone offset (e.g. +00:00 → UTC)
                    try:
                        return datetime.datetime.fromisoformat(ts_str)
                    except ValueError:
                        # Strip sub-second precision if fromisoformat chokes
                        ts_str = re.sub(r"\.\d+", "", ts_str)
                        return datetime.datetime.fromisoformat(ts_str)
    except OSError:
        return None
    return None


def _git_last_commit_time(path: Path) -> datetime.datetime | None:
    """Return the UTC datetime of the last git commit that touched *path*.

    Falls back to ``None`` if git is unavailable or the file is untracked.
    This is used instead of ``stat().st_mtime`` so that the check is
    stable in CI environments where ``git checkout`` resets all file
    mtimes to the checkout time.
    """
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%cI", "--", str(path)],
            capture_output=True,
            text=True,
            check=True,
            cwd=path.parent if path.is_file() else path,
        )
        ts_str = result.stdout.strip()
        if not ts_str:
            return None
        return datetime.datetime.fromisoformat(ts_str)
    except (subprocess.CalledProcessError, FileNotFoundError, ValueError):
        return None


def check_freshness(verbose: bool = False) -> list[str]:
    """Return a list of staleness error messages (empty = all fresh)."""
    errors: list[str] = []

    # Determine source files — prefer the new multi-source directory, fall back
    # to the legacy single file for environments that haven't migrated yet.
    if _SOURCE_DIR.exists():
        source_files = sorted(_SOURCE_DIR.rglob("*.yaml"))
        source_label = f"directory {_SOURCE_DIR.relative_to(_REPO_ROOT)}"
    elif _SOURCE_LEGACY.exists():
        source_files = [_SOURCE_LEGACY]
        source_label = str(_SOURCE_LEGACY.relative_to(_REPO_ROOT))
    else:
        errors.append(
            f"STPA source not found: neither {_SOURCE_DIR} nor {_SOURCE_LEGACY} exists"
        )
        return errors

    if not source_files:
        errors.append(f"No YAML files found under {_SOURCE_DIR}")
        return errors

    # Use the latest (most recent) source timestamp across all source files.
    # This ensures that modifying any single source file is enough to mark
    # artifacts as stale.
    source_git_times = [_git_last_commit_time(f) for f in source_files]
    valid_git_times = [t for t in source_git_times if t is not None]
    if valid_git_times:
        source_mtime_dt = max(valid_git_times)
        source_time_label = "git commit (newest source)"
        # Raw mtime needed for Check 1 (file-level mtime comparison).
        source_mtime = max(f.stat().st_mtime for f in source_files)
    else:
        # Fallback for untracked files or environments without git.
        source_mtime = max(f.stat().st_mtime for f in source_files)
        source_mtime_dt = datetime.datetime.fromtimestamp(
            source_mtime, tz=datetime.timezone.utc
        )
        source_time_label = "mtime (git unavailable)"

    if verbose:
        print(f"Source:  {source_label} ({len(source_files)} file(s))")
        print(f"  {source_time_label}: {source_mtime_dt.isoformat()}")

    for artifact in _GENERATED_ARTIFACTS:
        if not artifact.exists():
            msg = (
                f"MISSING artifact: {artifact.relative_to(_REPO_ROOT)}\n"
                f"  Run: python -m src.gateway.governance.stpa_compiler compile"
            )
            errors.append(msg)
            if verbose:
                print(f"\n[MISSING] {artifact.relative_to(_REPO_ROOT)}")
            continue

        artifact_mtime = artifact.stat().st_mtime
        artifact_mtime_dt = datetime.datetime.fromtimestamp(
            artifact_mtime, tz=datetime.timezone.utc
        )
        embedded_ts = _parse_embedded_timestamp(artifact)

        if verbose:
            print(f"\nArtifact: {artifact.relative_to(_REPO_ROOT)}")
            print(f"  file mtime:    {artifact_mtime_dt.isoformat()}")
            print(
                f"  embedded ts:   {embedded_ts.isoformat() if embedded_ts else 'not found'}"
            )

        # Check 1: file mtime — artifact must be newer than source.
        # Skip this check in CI-like environments where git commit time is
        # used for the source reference, because all file mtimes are reset
        # to the checkout time and are therefore unreliable for ordering.
        if not valid_git_times and artifact_mtime < source_mtime:
            msg = (
                f"STALE (mtime): {artifact.relative_to(_REPO_ROOT)}\n"
                f"  artifact mtime: {artifact_mtime_dt.isoformat()}\n"
                f"  source  mtime:  {source_mtime_dt.isoformat()}\n"
                f"  Run: python -m src.gateway.governance.stpa_compiler compile"
            )
            errors.append(msg)
            if verbose:
                print("  [STALE] file mtime is older than source")
            continue

        # Check 2: embedded timestamp — must be >= source mtime (to the minute)
        if embedded_ts is not None:
            # Make embedded_ts timezone-aware if it isn't already
            if embedded_ts.tzinfo is None:
                embedded_ts = embedded_ts.replace(tzinfo=datetime.timezone.utc)
            if embedded_ts < source_mtime_dt:
                msg = (
                    f"STALE (embedded ts): {artifact.relative_to(_REPO_ROOT)}\n"
                    f"  embedded Generated: {embedded_ts.isoformat()}\n"
                    f"  source  mtime:      {source_mtime_dt.isoformat()}\n"
                    f"  Run: python -m src.gateway.governance.stpa_compiler compile"
                )
                errors.append(msg)
                if verbose:
                    print("  [STALE] embedded timestamp pre-dates source mtime")
                continue

        if verbose:
            print("  [OK]")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check that generated STPA artifacts are current."
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print per-artifact details.",
    )
    args = parser.parse_args()

    errors = check_freshness(verbose=args.verbose)

    if errors:
        print("\n=== STPA FRESHNESS CHECK FAILED ===", file=sys.stderr)
        for err in errors:
            print(f"\n  {err}", file=sys.stderr)
        print(
            "\nFix: python -m src.gateway.governance.stpa_compiler compile",
            file=sys.stderr,
        )
        return 1

    print("STPA freshness check passed — all artifacts are current.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
