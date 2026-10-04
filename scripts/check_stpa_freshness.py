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

Fails with exit code 1 if any generated STPA artifact does not match the
STPA sources (``config/stpa/`` plus each domain's ``config/stpa/``).

Content first (F-3): each artifact is regenerated in memory with the STPA
compiler and compared by sha256 with the file on disk, with the volatile
``generated_at`` / ``issued_at`` / ``expires_at`` / ``Generated:`` stamps
masked. A match is fresh and a mismatch is stale, whatever the commit order
says, so touching a source without changing what it compiles to no longer
fails the check, and an artifact committed after an unrelated source change
can no longer hide a real difference.

Only when an artifact cannot be regenerated here (compiler not importable,
``ruff`` missing for the formatted Python targets, a generation error) does
the check fall back to ordering, for that artifact alone:

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
import enum
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
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
    _REPO_ROOT / "config" / "sandbox" / "generated_sandbox_policy.yaml",
]

_CORE = "core"
_FINANCE = "finance"

#: How each artifact is produced: (source set, compiler target). The source
#: set ``core`` is ``config/stpa/*.yaml``; ``finance`` is the finance domain's
#: ``config/stpa/*.yaml``.
_ARTIFACT_RECIPES: dict[Path, tuple[str, str]] = {
    _GENERATED_ARTIFACTS[0]: (_FINANCE, "python"),
    _GENERATED_ARTIFACTS[1]: (_FINANCE, "langgraph"),
    _GENERATED_ARTIFACTS[2]: (_FINANCE, "ftra"),
    _GENERATED_ARTIFACTS[3]: (_CORE, "ftra"),
    _GENERATED_ARTIFACTS[4]: (_CORE, "opa"),
    _GENERATED_ARTIFACTS[5]: (_CORE, "nemo"),
    _GENERATED_ARTIFACTS[6]: (_CORE, "agp"),
    _GENERATED_ARTIFACTS[7]: (_CORE, "sandbox"),
}

#: Targets whose written form is passed through ``ruff format`` by the compiler.
_RUFF_FORMATTED = frozenset({"python", "langgraph"})

# Volatile stamps masked before hashing: every compile rewrites them.
_VOLATILE_STAMP_RE = re.compile(
    r'(Generated:\s*|"(?:generated_at|issued_at|expires_at)":\s*")'
    r"\d{4}-\d{2}-\d{2}T[^\s\"]*"
)


class ContentCheck(enum.Enum):
    MATCH = "match"
    DIFFERS = "differs"
    UNAVAILABLE = "unavailable"


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


def content_digest(text: str) -> str:
    """sha256 of *text* with the volatile generation stamps masked."""
    return hashlib.sha256(_VOLATILE_STAMP_RE.sub(r"\1<ts>", text).encode()).hexdigest()


def _ruff_binary() -> str | None:
    """The ruff the compiler would use (venv first, then PATH), or ``None``."""
    venv_ruff = Path(sys.executable).parent / "ruff"
    if venv_ruff.exists():
        return str(venv_ruff)
    return shutil.which("ruff")


def _ruff_formatted(text: str, ruff: str) -> str | None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "generated.py"
        path.write_text(text, encoding="utf-8")
        try:
            subprocess.run([ruff, "format", str(path)], check=True, capture_output=True)
        except (OSError, subprocess.CalledProcessError):
            return None
        return path.read_text(encoding="utf-8")


def _regenerate_all() -> dict[Path, str | None]:
    """Regenerate every artifact in memory; ``None`` where that is not possible here."""
    unavailable: dict[Path, str | None] = dict.fromkeys(_GENERATED_ARTIFACTS)
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    try:
        from src.gateway.governance import stpa_compiler
    except Exception:  # noqa: BLE001 — any import failure means "cannot regenerate"
        return unavailable

    source_dirs = {_CORE: _SOURCE_DIR}
    if _DOMAIN_STPA_DIRS:
        source_dirs[_FINANCE] = _DOMAIN_STPA_DIRS[0]
    generators = {
        "opa": stpa_compiler.generate_opa,
        "nemo": stpa_compiler.generate_nemo,
        "python": stpa_compiler.generate_python,
        "langgraph": stpa_compiler.generate_langgraph,
        "agp": stpa_compiler.generate_agp,
        "ftra": stpa_compiler.generate_terminal_registry,
        "sandbox": stpa_compiler.generate_sandbox_policy,
    }
    structures: dict[str, object | None] = {}
    for name, directory in source_dirs.items():
        files = sorted(directory.rglob("*.yaml")) if directory.exists() else []
        try:
            structures[name] = stpa_compiler.load_control_structures(files) if files else None
        except Exception:  # noqa: BLE001
            structures[name] = None

    ruff = _ruff_binary()
    regenerated = unavailable
    for artifact, (source, target) in _ARTIFACT_RECIPES.items():
        if artifact not in regenerated:
            continue
        cs = structures.get(source)
        if cs is None or (target in _RUFF_FORMATTED and ruff is None):
            continue
        try:
            text = generators[target](cs)
        except Exception:  # noqa: BLE001
            continue
        if target in _RUFF_FORMATTED and ruff is not None:
            text = _ruff_formatted(text, ruff)
        regenerated[artifact] = text
    return regenerated


def check_content(
    regenerated: dict[Path, str | None] | None = None,
) -> dict[Path, ContentCheck]:
    """Compare each artifact on disk with its in-memory regeneration (sha256)."""
    if regenerated is None:
        regenerated = _regenerate_all()
    results: dict[Path, ContentCheck] = {}
    for artifact in _GENERATED_ARTIFACTS:
        fresh = regenerated.get(artifact)
        if fresh is None or not artifact.exists():
            results[artifact] = ContentCheck.UNAVAILABLE
            continue
        on_disk = artifact.read_text(encoding="utf-8")
        same = content_digest(on_disk) == content_digest(fresh)
        results[artifact] = ContentCheck.MATCH if same else ContentCheck.DIFFERS
    return results


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


def _check_commit_order(
    source_commit: datetime.datetime, verbose: bool, artifacts: list[Path]
) -> list[str]:
    """Committed tree: each artifact must be committed at or after the newest source.

    Rebases and squash merges rewrite committer times, but they rewrite the
    source and the artifacts of one commit identically and keep the relative
    order of commits, so this comparison is stable where a comparison against
    the wall-clock ``Generated:`` stamp is not.
    """
    errors: list[str] = []
    for artifact in artifacts:
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


def _check_working_tree(
    source_files: list[Path], verbose: bool, artifacts: list[Path]
) -> list[str]:
    """Uncommitted edits: embedded ``Generated:`` stamp (or mtime) vs source mtime."""
    errors: list[str] = []
    source_mtime = max(f.stat().st_mtime for f in source_files)
    source_mtime_dt = datetime.datetime.fromtimestamp(
        source_mtime, tz=datetime.timezone.utc
    )
    if verbose:
        print(f"  newest source mtime: {source_mtime_dt.isoformat()}")
    for artifact in artifacts:
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


def check_freshness(
    verbose: bool = False,
    *,
    regenerated: dict[Path, str | None] | None = None,
) -> list[str]:
    """Return a list of staleness error messages (empty = all fresh).

    Content first: an artifact whose sha256 (stamps masked) equals that of its
    in-memory regeneration is fresh; one that differs is stale. Artifacts that
    cannot be regenerated here fall back to ordering:

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

    errors: list[str] = []
    fallback: list[Path] = []
    for artifact, verdict in check_content(regenerated).items():
        if verbose:
            print(f"  content {verdict.value:11s} {artifact.relative_to(_REPO_ROOT)}")
        if verdict is ContentCheck.DIFFERS:
            errors.append(_stale(artifact, "content differs from a fresh compile (sha256)"))
        elif verdict is ContentCheck.UNAVAILABLE:
            fallback.append(artifact)
    if not fallback:
        return errors
    return errors + _check_order(source_files, fallback, verbose)


def _check_order(source_files: list[Path], artifacts: list[Path], verbose: bool) -> list[str]:
    """Ordering fallback for artifacts the content check could not regenerate."""
    dirty = _git_dirty(source_files + _GENERATED_ARTIFACTS)
    source_times = [_git_last_commit_time(f) for f in source_files]
    if dirty == set() and source_times and all(t is not None for t in source_times):
        source_commit = max(t for t in source_times if t is not None)
        if verbose:
            print(
                f"  mode: committed tree; newest source commit {source_commit.isoformat()}"
            )
        return _check_commit_order(source_commit, verbose, artifacts)

    if verbose:
        print("  mode: working tree (uncommitted STPA changes or git unavailable)")
    return _check_working_tree(source_files, verbose, artifacts)


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
