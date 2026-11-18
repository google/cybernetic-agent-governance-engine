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

"""
check_stpa_freshness.py — CI staleness guard for generated STPA & OSCAL artifacts
==================================================================================

Verifies that every generated artifact derived from ``config/stpa/`` and
``src/cage_*/config/stpa/`` matches a fresh in-memory compilation by SHA-256
(with volatile generation timestamps masked).

Fail-Closed Invariant (POAM-2026-221)
-------------------------------------
Inability to perform any content check is a hard failure (exit code ``1``),
never a skip or commit-order fallback:
  1. ``stpa_compiler`` and ``oscal_ssp_exporter`` must import cleanly.
  2. Every artifact in ``_GENERATED_ARTIFACTS`` must exist on disk and must
     have a registered recipe in ``_ARTIFACT_RECIPES`` or ``_OSCAL_TARGETS``
     (unless explicit ``regenerated`` content is supplied by a caller).
  3. ``ruff`` must be available whenever any active recipe target requires
     formatting (``_RUFF_FORMATTED``), and formatting failures fail closed.
  4. Any ``None`` or empty in-memory regeneration result fails closed.

Usage:
    uv run python scripts/check_stpa_freshness.py
    uv run python scripts/check_stpa_freshness.py --verbose

Exit codes:
    0 — all generated artifacts exist and match a fresh in-memory compile
    1 — one or more artifacts are missing, stale, or unable to be checked
"""

from __future__ import annotations

import argparse
import enum
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

os.environ.setdefault("CAGE_ENV", "ci")

# ---------------------------------------------------------------------------
# Paths (relative to repo root)
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[1]

# Multi-source directories — core_system.yaml + discovered domain STPA YAML dirs.
_SOURCE_DIR = _REPO_ROOT / "config" / "stpa"
_DOMAIN_STPA_DIRS: list[Path] = [
    d
    for d in sorted((_REPO_ROOT / "src").glob("cage_*/config/stpa"))
    if any(d.glob("*.yaml"))
]

_OSCAL_SSP = _REPO_ROOT / "compliance" / "oscal" / "system-security-plan.yaml"
_OSCAL_COMP_DEF = _REPO_ROOT / "compliance" / "oscal" / "component-definition.yaml"
_OSCAL_PATCH = _REPO_ROOT / "compliance" / "oscal" / "stpa_compiler_ssp_patch.yaml"

_CORE = "core"


def _domain_key_for(stpa_dir: Path) -> str:
    return stpa_dir.parent.parent.name.removeprefix("cage_")


def _build_artifact_recipes(
    domain_dirs: list[Path],
) -> tuple[list[Path], dict[Path, tuple[str, str]]]:
    artifacts: list[Path] = []
    recipes: dict[Path, tuple[str, str]] = {}
    for d_dir in domain_dirs:
        key = _domain_key_for(d_dir)
        out_dir = d_dir.parent.parent / "stpa"
        for filename, target in (
            ("uca_rules.py", "python"),
            ("saga_nodes.py", "langgraph"),
            ("terminal_registry.json", "ftra"),
        ):
            art = out_dir / filename
            artifacts.append(art)
            recipes[art] = (key, target)
    core_ftra = (
        _REPO_ROOT / "src" / "gateway" / "governance" / "terminal_action_registry.json"
    )
    core_nemo = _REPO_ROOT / "config" / "rails" / "generated_stpa_rails.co"
    core_sandbox = _REPO_ROOT / "config" / "sandbox" / "generated_sandbox_policy.yaml"
    for art, target in (
        (core_ftra, "ftra"),
        (core_nemo, "nemo"),
        (core_sandbox, "sandbox"),
    ):
        artifacts.append(art)
        recipes[art] = (_CORE, target)
    artifacts.extend([_OSCAL_SSP, _OSCAL_COMP_DEF, _OSCAL_PATCH])
    return artifacts, recipes


_BUILT_RECIPES = _build_artifact_recipes(_DOMAIN_STPA_DIRS)
_GENERATED_ARTIFACTS: list[Path] = _BUILT_RECIPES[0]
_ARTIFACT_RECIPES: dict[Path, tuple[str, str]] = _BUILT_RECIPES[1]

#: Targets whose written form is passed through ``ruff format`` by the compiler.
_RUFF_FORMATTED = frozenset({"python", "langgraph"})

# Volatile stamps masked before hashing: every compile/export rewrites them.
# Covers STPA compiler headers/JSON fields as well as the OSCAL SSP/Component
# timestamp locations (last-modified, generated, props[last-compiled]). The
# exporter writes no stamp into an implemented-requirement, whose text the
# evidence-claim census hashes.
_VOLATILE_STAMP_RE = re.compile(
    r"("
    r"Generated:\s*"
    r'|"(?:generated_at|issued_at|expires_at)":\s*"'
    r"|(?:last-modified|generated):\s*['\"]?"
    r"|-\s*name:\s*last-compiled\s*\n\s*value:\s*['\"]?"
    r")"
    r"\d{4}-\d{2}-\d{2}T[^\s\"'\\]*"
)


class ContentCheck(enum.Enum):
    MATCH = "match"
    DIFFERS = "differs"
    MISSING = "missing"
    UNABLE_TO_CHECK = "unable_to_check"


def content_digest(text: str) -> str:
    """sha256 of *text* with the volatile generation stamps masked."""
    return hashlib.sha256(_VOLATILE_STAMP_RE.sub(r"\1<ts>", text).encode()).hexdigest()


def _ruff_binary() -> str | None:
    """The ruff the compiler would use (venv first, then PATH), or ``None``."""
    venv_ruff = Path(sys.executable).parent / "ruff"
    if venv_ruff.exists():
        return str(venv_ruff)
    return shutil.which("ruff")


def _ruff_formatted(text: str, ruff: str) -> str:
    """Format *text* with *ruff*, failing closed on non-zero exit or OS error."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "generated.py"
        path.write_text(text, encoding="utf-8")
        try:
            subprocess.run(
                [ruff, "format", str(path)],
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise RuntimeError(
                f"ruff format failed for generated target: {exc}"
            ) from exc
        return path.read_text(encoding="utf-8")


def _oscal_targets() -> tuple[Path, Path, Path]:
    return (_OSCAL_SSP, _OSCAL_COMP_DEF, _OSCAL_PATCH)


def _regenerate_all() -> dict[Path, str | None]:
    """Regenerate every configured artifact in memory, failing closed if unable."""
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))

    from src.gateway.governance import stpa_compiler

    oscal_set = set(_oscal_targets())
    unregistered = [
        art
        for art in _GENERATED_ARTIFACTS
        if art not in _ARTIFACT_RECIPES and art not in oscal_set
    ]
    if unregistered:
        joined = ", ".join(str(_rel(p)) for p in unregistered)
        raise RuntimeError(
            f"UNABLE TO CHECK: artifact(s) have no registered regeneration recipe: {joined}"
        )

    source_dirs = {_CORE: _SOURCE_DIR}
    for d_dir in _DOMAIN_STPA_DIRS:
        source_dirs[_domain_key_for(d_dir)] = d_dir
    generators: dict[str, Any] = {
        "opa": stpa_compiler.generate_opa,
        "nemo": stpa_compiler.generate_nemo,
        "python": stpa_compiler.generate_python,
        "langgraph": stpa_compiler.generate_langgraph,
        "ftra": stpa_compiler.generate_terminal_registry,
        "sandbox": stpa_compiler.generate_sandbox_policy,
    }

    active_artifacts = set(_GENERATED_ARTIFACTS)
    needed_sources = {
        source
        for artifact, (source, _target) in _ARTIFACT_RECIPES.items()
        if artifact in active_artifacts
    }
    needs_ruff = any(
        target in _RUFF_FORMATTED
        for artifact, (_source, target) in _ARTIFACT_RECIPES.items()
        if artifact in active_artifacts
    )
    ruff = _ruff_binary()
    if needs_ruff and ruff is None:
        raise RuntimeError(
            "UNABLE TO CHECK: ruff binary is required to verify formatted Python/LangGraph STPA targets"
        )

    structures: dict[str, Any] = {}
    for name, directory in source_dirs.items():
        if name not in needed_sources:
            continue
        files = sorted(directory.rglob("*.yaml")) if directory.exists() else []
        if not files:
            raise RuntimeError(
                f"UNABLE TO CHECK: no STPA YAML files found for source '{name}' under {directory}"
            )
        structures[name] = stpa_compiler.load_control_structures(files)

    regenerated: dict[Path, str | None] = dict.fromkeys(_GENERATED_ARTIFACTS)
    for artifact, (source, target) in _ARTIFACT_RECIPES.items():
        if artifact not in regenerated:
            continue
        cs = structures.get(source)
        if cs is None:
            raise RuntimeError(
                f"UNABLE TO CHECK: missing compiled control structure '{source}' for {_rel(artifact)}"
            )
        text: str | None = generators[target](cs)
        if text is None:
            raise RuntimeError(
                f"UNABLE TO CHECK: generator '{target}' returned None for {_rel(artifact)}"
            )
        if target in _RUFF_FORMATTED:
            assert ruff is not None
            text = _ruff_formatted(text, ruff)
        regenerated[artifact] = text

    if any(p in regenerated for p in oscal_set):
        missing_oscal_on_disk = [
            p for p in _oscal_targets() if p in regenerated and not p.exists()
        ]
        if not missing_oscal_on_disk:
            from src.gateway.governance.oscal_ssp_exporter import (
                render_default_oscal_artifacts,
            )

            oscal_rendered = render_default_oscal_artifacts(
                ssp_path=_OSCAL_SSP,
                comp_def_path=_OSCAL_COMP_DEF,
                patch_out_path=_OSCAL_PATCH,
                raise_on_error=True,
            )
            for p, rendered_text in oscal_rendered.items():
                if p in regenerated:
                    regenerated[p] = rendered_text

    return regenerated


def check_content(
    regenerated: dict[Path, str | None] | None = None,
) -> dict[Path, ContentCheck]:
    """Compare each artifact on disk with its in-memory regeneration (sha256)."""
    if regenerated is None:
        regenerated = _regenerate_all()
    results: dict[Path, ContentCheck] = {}
    for artifact in _GENERATED_ARTIFACTS:
        if not artifact.exists():
            results[artifact] = ContentCheck.MISSING
            continue
        fresh = regenerated.get(artifact)
        if fresh is None:
            results[artifact] = ContentCheck.UNABLE_TO_CHECK
            continue
        on_disk = artifact.read_text(encoding="utf-8")
        same = content_digest(on_disk) == content_digest(fresh)
        results[artifact] = ContentCheck.MATCH if same else ContentCheck.DIFFERS
    return results


def _rel(artifact: Path) -> Path:
    try:
        return artifact.relative_to(_REPO_ROOT)
    except ValueError:
        return artifact


def _remediation_cmd(artifact: Path) -> str:
    return (
        "python -m src.gateway.governance.oscal_ssp_exporter export"
        if artifact in _oscal_targets()
        else "python -m src.gateway.governance.stpa_compiler compile"
    )


def _stale(artifact: Path, reason: str) -> str:
    return f"STALE ({reason}): {_rel(artifact)}\n  Run: {_remediation_cmd(artifact)}"


def check_freshness(
    verbose: bool = False,
    *,
    regenerated: dict[Path, str | None] | None = None,
) -> list[str]:
    """Return a list of staleness or inability-to-check error messages (empty = all fresh).

    Every artifact must exist on disk and match the SHA-256 (volatile timestamps
    masked) of its fresh in-memory regeneration. Inability to import compiler
    or exporter dependencies, missing ``ruff`` on formatted targets, missing
    files, or ``None`` regeneration results are reported as hard errors — never
    downgraded to commit-order fallbacks (POAM-2026-221).
    """
    if not _SOURCE_DIR.exists():
        return [f"STPA source directory not found: {_SOURCE_DIR}"]
    source_files = sorted(_SOURCE_DIR.rglob("*.yaml"))
    for d_dir in _DOMAIN_STPA_DIRS:
        if d_dir.exists():
            source_files.extend(sorted(d_dir.rglob("*.yaml")))
    source_label = f"directory {_rel(_SOURCE_DIR)} + domain STPA dirs"
    if not source_files:
        return [f"No YAML files found under {_SOURCE_DIR}"]

    if verbose:
        print(f"Source:  {source_label} ({len(source_files)} file(s))")

    try:
        verdicts = check_content(regenerated)
    except Exception as exc:  # noqa: BLE001 — convert precondition/import failure to hard gate error
        return [
            f"UNABLE TO CHECK STPA/OSCAL artifact freshness ({type(exc).__name__}): {exc}"
        ]

    errors: list[str] = []
    for artifact, verdict in verdicts.items():
        if verbose:
            print(f"  content {verdict.value:15s} {_rel(artifact)}")
        if verdict is ContentCheck.MISSING:
            errors.append(
                f"MISSING artifact: {_rel(artifact)}\n  Run: {_remediation_cmd(artifact)}"
            )
        elif verdict is ContentCheck.UNABLE_TO_CHECK:
            errors.append(
                f"UNABLE TO CHECK (in-memory regeneration produced no output): {_rel(artifact)}\n"
                f"  Run: {_remediation_cmd(artifact)}"
            )
        elif verdict is ContentCheck.DIFFERS:
            errors.append(
                _stale(artifact, "content differs from a fresh compile (sha256)")
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check that generated STPA and OSCAL artifacts are current."
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
            "\nFix: uv run python -m src.gateway.governance.stpa_compiler compile && "
            "uv run python -m src.gateway.governance.oscal_ssp_exporter export",
            file=sys.stderr,
        )
        return 1

    print("STPA freshness check passed — all artifacts are current.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
