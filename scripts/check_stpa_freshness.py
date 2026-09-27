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

Fails with exit code 1 if any generated STPA artifact is older than the
STPA sources (``config/stpa/`` plus each domain's ``config/stpa/``):

* In a committed tree (CI) an artifact is stale if its last commit precedes
  the newest source commit. Commit *order* survives rebases and squash
  merges, which rewrite committer times; the wall-clock ``Generated:`` stamp
  does not.
* With uncommitted STPA edits, an artifact is stale if its ``Generated:``
  stamp (or mtime) pre-dates the newest source file mtime.

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

# Multi-source directories — core_system.yaml + domain STPA YAML files.
_SOURCE_DIR = _REPO_ROOT / "config" / "stpa"
_DOMAIN_STPA_DIRS: list[Path] = [
    _REPO_ROOT / "src" / "cage_finance" / "config" / "stpa",
]
# Fallback single-file path for environments that have not yet migrated.
_SOURCE_LEGACY = _REPO_ROOT / "config" / "stpa_control_structure.yaml"

_GENERATED_ARTIFACTS: list[Path] = [
    _REPO_ROOT / "src" / "cage_finance" / "stpa" / "uca_rules.py",
    _REPO_ROOT / "src" / "cage_finance" / "stpa" / "saga_nodes.py",
    _REPO_ROOT / "src" / "cage_finance" / "stpa" / "terminal_registry.json",
    _REPO_ROOT / "src" / "gateway" / "governance" / "terminal_action_registry.json",
    _REPO_ROOT / "config" / "opa" / "generated_stpa_policy.rego",
    _REPO_ROOT / "config" / "rails" / "generated_stpa_rails.co",
    _REPO_ROOT / "config" / "agp" / "generated_semantic_policy.txt",
]

# Regex that matches the "Generated: <ISO-8601>" comment or "generated_at": "<ISO-8601>" JSON field.
_GENERATED_TS_RE = re.compile(
    r'(?:Generated:\s*|"generated_at":\s*")(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s"]*)'
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


def _git_dirty(paths: list[Path]) -> set[Path] | None:
    """Return the subset of *paths* with uncommitted changes, or ``None`` without git."""
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain", "--", *(str(p) for p in paths)],
            capture_output=True,
            text=True,
            check=True,
            cwd=_REPO_ROOT,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    dirty: set[Path] = set()
    for line in result.stdout.splitlines():
        rel = line[3:].split(" -> ")[-1].strip().strip('"')
        if rel:
            dirty.add((_REPO_ROOT / rel).resolve())
    return dirty


def _stale(artifact: Path, reason: str) -> str:
    return (
        f"STALE ({reason}): {artifact.relative_to(_REPO_ROOT)}\n"
        f"  Run: python -m src.gateway.governance.stpa_compiler compile"
    )


def _check_commit_order(source_commit: datetime.datetime, verbose: bool) -> list[str]:
    """Committed tree: each artifact must be committed at or after the newest source.

    Rebases and squash merges rewrite committer times, but they rewrite the
    source and the artifacts of one commit identically and keep the relative
    order of commits, so this comparison is stable where a comparison against
    the wall-clock ``Generated:`` stamp is not.
    """
    errors: list[str] = []
    for artifact in _GENERATED_ARTIFACTS:
        if not artifact.exists():
            errors.append(
                f"MISSING artifact: {artifact.relative_to(_REPO_ROOT)}\n"
                f"  Run: python -m src.gateway.governance.stpa_compiler compile"
            )
            continue
        artifact_commit = _git_last_commit_time(artifact)
        if verbose:
            print(f"\nArtifact: {artifact.relative_to(_REPO_ROOT)}")
            print(
                f"  last commit:   {artifact_commit.isoformat() if artifact_commit else 'untracked'}"
            )
        if artifact_commit is None or artifact_commit < source_commit:
            errors.append(
                _stale(artifact, "committed before newest STPA source change")
                + f"\n  artifact commit: {artifact_commit.isoformat() if artifact_commit else 'untracked'}"
                + f"\n  source   commit: {source_commit.isoformat()}"
            )
            if verbose:
                print("  [STALE] artifact committed before newest source")
            continue
        if verbose:
            print("  [OK]")
    return errors


def _check_working_tree(source_files: list[Path], verbose: bool) -> list[str]:
    """Uncommitted edits: embedded ``Generated:`` stamp (or mtime) vs source mtime."""
    errors: list[str] = []
    source_mtime = max(f.stat().st_mtime for f in source_files)
    source_mtime_dt = datetime.datetime.fromtimestamp(
        source_mtime, tz=datetime.timezone.utc
    )
    if verbose:
        print(f"  newest source mtime: {source_mtime_dt.isoformat()}")
    for artifact in _GENERATED_ARTIFACTS:
        if not artifact.exists():
            errors.append(
                f"MISSING artifact: {artifact.relative_to(_REPO_ROOT)}\n"
                f"  Run: python -m src.gateway.governance.stpa_compiler compile"
            )
            continue
        embedded_ts = _parse_embedded_timestamp(artifact)
        if embedded_ts is not None and embedded_ts.tzinfo is None:
            embedded_ts = embedded_ts.replace(tzinfo=datetime.timezone.utc)
        artifact_dt = embedded_ts or datetime.datetime.fromtimestamp(
            artifact.stat().st_mtime, tz=datetime.timezone.utc
        )
        if verbose:
            print(f"\nArtifact: {artifact.relative_to(_REPO_ROOT)}")
            print(f"  generated:     {artifact_dt.isoformat()}")
        if artifact_dt < source_mtime_dt:
            errors.append(
                _stale(artifact, "generated before source edit")
                + f"\n  generated:    {artifact_dt.isoformat()}"
                + f"\n  source mtime: {source_mtime_dt.isoformat()}"
            )
            if verbose:
                print("  [STALE] generated before source edit")
            continue
        if verbose:
            print("  [OK]")
    return errors


def check_freshness(verbose: bool = False) -> list[str]:
    """Return a list of staleness error messages (empty = all fresh).

    * **Committed tree** (CI, or a clean local checkout): every artifact must
      be committed at or after the newest STPA source change (git commit
      order).
    * **Uncommitted edits** to any source or artifact: every artifact's
      embedded ``Generated:`` stamp (or file mtime) must not pre-date the
      newest source file mtime.
    """
    if _SOURCE_DIR.exists():
        source_files = sorted(_SOURCE_DIR.rglob("*.yaml"))
        for d_dir in _DOMAIN_STPA_DIRS:
            if d_dir.exists():
                source_files.extend(sorted(d_dir.rglob("*.yaml")))
        source_label = (
            f"directory {_SOURCE_DIR.relative_to(_REPO_ROOT)} + domain STPA dirs"
        )
    elif _SOURCE_LEGACY.exists():
        source_files = [_SOURCE_LEGACY]
        source_label = str(_SOURCE_LEGACY.relative_to(_REPO_ROOT))
    else:
        return [
            f"STPA source not found: neither {_SOURCE_DIR} nor {_SOURCE_LEGACY} exists"
        ]
    if not source_files:
        return [f"No YAML files found under {_SOURCE_DIR}"]

    if verbose:
        print(f"Source:  {source_label} ({len(source_files)} file(s))")

    dirty = _git_dirty(source_files + _GENERATED_ARTIFACTS)
    source_times = [_git_last_commit_time(f) for f in source_files]
    if dirty == set() and source_times and all(t is not None for t in source_times):
        source_commit = max(t for t in source_times if t is not None)
        if verbose:
            print(
                f"  mode: committed tree; newest source commit {source_commit.isoformat()}"
            )
        return _check_commit_order(source_commit, verbose)

    if verbose:
        print("  mode: working tree (uncommitted STPA changes or git unavailable)")
    return _check_working_tree(source_files, verbose)


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
