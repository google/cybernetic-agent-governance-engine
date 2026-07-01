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
check_lula_stub_count.py — CI gate for Lula stub manifest accumulation
=======================================================================

Scans all ``.yaml`` files in ``compliance/lula/`` and identifies stub
manifests — those that contain placeholder logic that always passes
``lula validate`` without actually verifying any Kubernetes resources.

A manifest is classified as a **stub** if ANY of the following are true:

1. The Rego policy body contains ``default allow = true`` (allow-all stub).
2. The ``domain`` section has an empty ``resources`` list or no ``resources``
   key at all (no resources to check → nothing is actually validated).
3. The manifest metadata/description/notes contains ``NotImplemented``,
   ``TODO``, ``STUB``, or ``placeholder`` (case-insensitive).
4. The Rego policy has fewer than 3 meaningful rule lines (i.e., only a
   ``default allow = true`` and nothing substantive).

The script then:

- Reads ``docs/POAM.md`` and checks whether each stub manifest is
  referenced by at least one POAM entry.
- Compares the current stub count against the baseline stored in
  ``compliance/lula/.stub-baseline``.
- Exits 0 if stub count ≤ baseline AND all stubs have POAM entries.
- Exits 1 if stub count > baseline (new stubs added without updating
  baseline) OR any stub lacks a POAM entry.

Usage::

    # In CI — fails if stub count grew or a stub lacks a POAM entry
    python scripts/check_lula_stub_count.py

    # After intentionally adding a new stub with a POAM entry:
    python scripts/check_lula_stub_count.py --update-baseline

Exit codes:
    0  All checks passed.
    1  Stub count exceeded baseline, or a stub lacks a POAM entry.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import NamedTuple

try:
    import yaml
except ImportError:
    print(
        "ERROR: PyYAML is required. Install with: pip install pyyaml",
        file=sys.stderr,
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Paths (relative to repo root)
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[1]
_LULA_DIR = _REPO_ROOT / "compliance" / "lula"
_BASELINE_FILE = _LULA_DIR / ".stub-baseline"
_POAM_FILE = _REPO_ROOT / "docs" / "POAM.md"

# ---------------------------------------------------------------------------
# Stub detection patterns
# ---------------------------------------------------------------------------

# Rego lines that are NOT meaningful rules (comments, blank lines, package
# declarations, import statements, and the stub allow-all default).
_REGO_NOISE_RE = re.compile(
    r"^\s*("
    r"#.*"                          # comment
    r"|package\s+\w+"               # package declaration
    r"|import\s+.*"                 # import statement
    r"|default\s+allow\s*=\s*true"  # the stub itself
    r"|default\s+validate\s*=\s*false"  # common default
    r"|)\s*$"                       # blank line
)

# Metadata-level stub markers (case-insensitive search in the raw YAML text)
_STUB_MARKERS = ("NotImplemented", "TODO", "STUB", "placeholder")


class ManifestResult(NamedTuple):
    name: str
    is_stub: bool
    stub_reasons: list[str]
    has_poam: bool
    poam_ids: list[str]


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


def _rego_meaningful_line_count(rego_text: str) -> int:
    """Count non-noise lines in a Rego policy body."""
    return sum(
        1
        for line in rego_text.splitlines()
        if not _REGO_NOISE_RE.match(line)
    )


def _extract_rego_bodies(doc: dict) -> list[str]:
    """Return all Rego policy bodies found in a parsed YAML document."""
    bodies: list[str] = []
    provider = doc.get("provider", {})
    if not isinstance(provider, dict):
        return bodies

    # Support both opa-spec.rego and opa.policy key variants
    opa_spec = provider.get("opa-spec") or provider.get("opa") or {}
    if isinstance(opa_spec, dict):
        rego = opa_spec.get("rego") or opa_spec.get("policy")
        if isinstance(rego, str):
            bodies.append(rego)

    return bodies


def _has_empty_resources(doc: dict) -> bool:
    """Return True if the domain section has an empty or absent resources list."""
    domain = doc.get("domain", {})
    if not isinstance(domain, dict):
        return False

    domain_type = domain.get("type", "")

    # Only kubernetes domains have a resources list to check
    if domain_type != "kubernetes":
        return False

    # Support both kubernetes-spec and kubernetes key variants
    k8s_spec = domain.get("kubernetes-spec") or domain.get("kubernetes") or {}
    if not isinstance(k8s_spec, dict):
        return True  # malformed → treat as stub

    resources = k8s_spec.get("resources")
    if resources is None:
        return True  # no resources key
    if isinstance(resources, list) and len(resources) == 0:
        return True  # empty list

    return False


def _has_stub_markers_in_doc(doc: dict) -> list[str]:
    """
    Return list of stub markers found in the manifest's metadata and
    top-level structured fields (annotations, labels, description).

    Deliberately excludes ``notes`` and free-text comment blocks so that
    manifests that merely *mention* stubs in their explanatory prose are
    not incorrectly flagged.  The Rego policy body is also excluded here
    because ``default allow = true`` is caught by the dedicated Rego check.
    """
    found: list[str] = []

    # Collect candidate strings from structured metadata fields only
    candidates: list[str] = []

    metadata = doc.get("metadata", {})
    if isinstance(metadata, dict):
        candidates.append(str(metadata.get("name", "")))
        annotations = metadata.get("annotations", {})
        if isinstance(annotations, dict):
            candidates.extend(str(v) for v in annotations.values())
        labels = metadata.get("labels", {})
        if isinstance(labels, dict):
            candidates.extend(str(v) for v in labels.values())

    description = doc.get("description", "")
    if description:
        candidates.append(str(description))

    combined = " ".join(candidates).lower()
    for marker in _STUB_MARKERS:
        if marker.lower() in combined:
            found.append(marker)

    return found


def classify_manifest(path: Path) -> ManifestResult:
    """Classify a single Lula manifest as stub or active."""
    raw_text = path.read_text(encoding="utf-8")
    stub_reasons: list[str] = []

    try:
        doc = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        # Unparseable YAML — flag as stub so it gets attention
        stub_reasons.append(f"YAML parse error: {exc}")
        return ManifestResult(
            name=path.name,
            is_stub=True,
            stub_reasons=stub_reasons,
            has_poam=False,
            poam_ids=[],
        )

    if not isinstance(doc, dict):
        stub_reasons.append("document is not a YAML mapping")
        return ManifestResult(
            name=path.name,
            is_stub=True,
            stub_reasons=stub_reasons,
            has_poam=False,
            poam_ids=[],
        )

    # Check 1: default allow = true in any Rego body
    for rego in _extract_rego_bodies(doc):
        if re.search(r"\bdefault\s+allow\s*=\s*true\b", rego):
            stub_reasons.append("Rego contains 'default allow = true' (allow-all stub)")
        # Check 4: fewer than 3 meaningful rule lines
        meaningful = _rego_meaningful_line_count(rego)
        if meaningful < 3:
            stub_reasons.append(
                f"Rego has only {meaningful} meaningful rule line(s) "
                f"(threshold: 3) — policy body is effectively empty"
            )

    # Check 2: empty or absent resources list in kubernetes domain
    if _has_empty_resources(doc):
        stub_reasons.append(
            "domain.kubernetes-spec.resources is empty or absent "
            "(no Kubernetes resources to validate)"
        )

    # Check 3: stub markers in structured metadata fields (not free-text notes)
    markers = _has_stub_markers_in_doc(doc)
    if markers:
        stub_reasons.append(
            f"metadata annotations/labels contain stub marker(s): {', '.join(markers)}"
        )

    # Deduplicate reasons while preserving order
    seen: set[str] = set()
    unique_reasons: list[str] = []
    for r in stub_reasons:
        if r not in seen:
            seen.add(r)
            unique_reasons.append(r)

    return ManifestResult(
        name=path.name,
        is_stub=bool(unique_reasons),
        stub_reasons=unique_reasons,
        has_poam=False,   # filled in by check_poam_coverage()
        poam_ids=[],      # filled in by check_poam_coverage()
    )


# ---------------------------------------------------------------------------
# POAM coverage
# ---------------------------------------------------------------------------


def _load_poam_references(poam_path: Path) -> dict[str, list[str]]:
    """
    Parse docs/POAM.md and return a mapping of manifest filename →
    list of POAM IDs that reference it.

    A POAM entry is considered to reference a manifest if the manifest
    filename appears anywhere in the entry's text block.
    """
    if not poam_path.exists():
        return {}

    text = poam_path.read_text(encoding="utf-8")

    # Split on POAM entry headings (### POAM-... or ### EU-... or ### APAC-...)
    entry_pattern = re.compile(
        r"^###\s+(POAM-[\w-]+|EU-[\w-]+|APAC-[\w-]+)",
        re.MULTILINE,
    )
    splits = entry_pattern.split(text)
    # splits: [preamble, id1, body1, id2, body2, ...]

    manifest_to_poam: dict[str, list[str]] = {}

    it = iter(splits[1:])  # skip preamble
    for poam_id, body in zip(it, it):
        # Find all manifest filenames mentioned in this entry's body
        for match in re.finditer(r"lula-validation-[\w-]+\.yaml", body):
            fname = match.group(0)
            manifest_to_poam.setdefault(fname, [])
            if poam_id not in manifest_to_poam[fname]:
                manifest_to_poam[fname].append(poam_id)

    return manifest_to_poam


def check_poam_coverage(
    results: list[ManifestResult],
    poam_refs: dict[str, list[str]],
) -> list[ManifestResult]:
    """Annotate each stub result with its POAM coverage."""
    updated: list[ManifestResult] = []
    for r in results:
        if r.is_stub:
            ids = poam_refs.get(r.name, [])
            updated.append(
                ManifestResult(
                    name=r.name,
                    is_stub=r.is_stub,
                    stub_reasons=r.stub_reasons,
                    has_poam=bool(ids),
                    poam_ids=ids,
                )
            )
        else:
            updated.append(r)
    return updated


# ---------------------------------------------------------------------------
# Baseline I/O
# ---------------------------------------------------------------------------


def _read_baseline() -> int | None:
    """Read the stub count baseline. Returns None if the file does not exist."""
    if not _BASELINE_FILE.exists():
        return None
    try:
        return int(_BASELINE_FILE.read_text(encoding="utf-8").strip())
    except ValueError:
        return None


def _write_baseline(count: int) -> None:
    """Write the stub count baseline."""
    _BASELINE_FILE.write_text(f"{count}\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

_COL_NAME = 52
_COL_STUB = 8
_COL_POAM = 30


def _print_table(results: list[ManifestResult]) -> None:
    header = (
        f"{'Manifest':<{_COL_NAME}} {'Stub?':<{_COL_STUB}} {'POAM IDs':<{_COL_POAM}}"
    )
    sep = "-" * len(header)
    print(header)
    print(sep)
    for r in sorted(results, key=lambda x: x.name):
        stub_label = "YES" if r.is_stub else "no"
        poam_label = ", ".join(r.poam_ids) if r.poam_ids else ("—" if r.is_stub else "")
        print(f"{r.name:<{_COL_NAME}} {stub_label:<{_COL_STUB}} {poam_label:<{_COL_POAM}}")
    print(sep)


def _print_stub_details(results: list[ManifestResult]) -> None:
    stubs = [r for r in results if r.is_stub]
    if not stubs:
        return
    print("\nStub detection details:")
    for r in stubs:
        print(f"\n  {r.name}")
        for reason in r.stub_reasons:
            print(f"    • {reason}")
        if r.has_poam:
            print(f"    ✓ POAM entry: {', '.join(r.poam_ids)}")
        else:
            print("    ✗ NO POAM ENTRY — add one to docs/POAM.md")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "CI gate: fail if the number of stub Lula manifests grows "
            "without a corresponding POAM entry."
        )
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help=(
            "Write the current stub count to compliance/lula/.stub-baseline. "
            "Use this after adding a POAM entry for a new stub."
        ),
    )
    args = parser.parse_args()

    # ------------------------------------------------------------------
    # 1. Scan manifests
    # ------------------------------------------------------------------
    yaml_files = sorted(_LULA_DIR.glob("*.yaml"))
    if not yaml_files:
        print(f"ERROR: no .yaml files found in {_LULA_DIR}", file=sys.stderr)
        return 1

    results = [classify_manifest(f) for f in yaml_files]

    # ------------------------------------------------------------------
    # 2. Check POAM coverage
    # ------------------------------------------------------------------
    poam_refs = _load_poam_references(_POAM_FILE)
    results = check_poam_coverage(results, poam_refs)

    stubs = [r for r in results if r.is_stub]
    stub_count = len(stubs)
    stubs_without_poam = [r for r in stubs if not r.has_poam]

    # ------------------------------------------------------------------
    # 3. Print summary table
    # ------------------------------------------------------------------
    print(f"\n=== Lula Stub Count Gate ===")
    print(f"Scanned {len(results)} manifest(s) in {_LULA_DIR.relative_to(_REPO_ROOT)}")
    print(f"Stubs found: {stub_count}\n")
    _print_table(results)
    _print_stub_details(results)

    # ------------------------------------------------------------------
    # 4. --update-baseline mode
    # ------------------------------------------------------------------
    if args.update_baseline:
        _write_baseline(stub_count)
        print(
            f"\n✓ Baseline updated: {_BASELINE_FILE.relative_to(_REPO_ROOT)} "
            f"← {stub_count}"
        )
        if stubs_without_poam:
            print(
                "\n⚠  WARNING: the following stubs still lack POAM entries:",
                file=sys.stderr,
            )
            for r in stubs_without_poam:
                print(f"   • {r.name}", file=sys.stderr)
            print(
                "\n   Add POAM entries in docs/POAM.md before merging.",
                file=sys.stderr,
            )
            return 1
        return 0

    # ------------------------------------------------------------------
    # 5. Read baseline and compare
    # ------------------------------------------------------------------
    baseline = _read_baseline()
    failures: list[str] = []

    if baseline is None:
        failures.append(
            f"Baseline file not found: {_BASELINE_FILE.relative_to(_REPO_ROOT)}\n"
            f"  Fix: python scripts/check_lula_stub_count.py --update-baseline"
        )
    elif stub_count > baseline:
        failures.append(
            f"Stub count INCREASED: {stub_count} > baseline {baseline}\n"
            f"  New stubs were added without updating the baseline.\n"
            f"  Fix:\n"
            f"    1. Add a POAM entry in docs/POAM.md for each new stub.\n"
            f"    2. Run: python scripts/check_lula_stub_count.py --update-baseline\n"
            f"    3. Commit both docs/POAM.md and "
            f"compliance/lula/.stub-baseline together."
        )
    else:
        print(f"\nBaseline: {baseline}  Current: {stub_count}  ✓ within baseline")

    if stubs_without_poam:
        names = ", ".join(r.name for r in stubs_without_poam)
        failures.append(
            f"Stub(s) without POAM entry: {names}\n"
            f"  Fix: Add POAM entries in docs/POAM.md for the listed manifests.\n"
            f"  Each entry must reference the manifest filename so this script\n"
            f"  can detect the association."
        )

    # ------------------------------------------------------------------
    # 6. Exit
    # ------------------------------------------------------------------
    if failures:
        print("\n=== LULA STUB GATE FAILED ===", file=sys.stderr)
        for i, msg in enumerate(failures, 1):
            print(f"\n[{i}] {msg}", file=sys.stderr)
        return 1

    print("\n✓ Lula stub gate passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
