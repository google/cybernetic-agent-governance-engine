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

Scans ``lula-validation-*.yaml`` manifests in ``compliance/lula/`` (supporting
both OSCAL ``component-definition`` documents with embedded
``back-matter.resources[].description`` Lula payloads and standalone top-level
``domain``/``provider`` documents) and enforces three fail-closed invariants:

1. **Non-vacuous corpus & per-manifest recognition floor**:
   - Every manifest must yield at least one extracted ``domain`` mapping and at
     least one non-empty OPA Rego policy body.
   - Across the corpus, total discovered manifests must meet ``--min-manifests``
     (default ``30`` on live repo scan) and total extracted Rego bodies must
     meet ``--min-rego-bodies`` (default ``30`` on live repo scan). A parser
     that recognizes nothing across a corpus fails closed rather than passing.

2. **Stub classification**:
   A manifest is classified as a **stub** if ANY of the following are true:
   - Any Rego policy body contains ``default allow = true`` (allow-all stub).
   - A ``kubernetes`` domain has an empty/absent ``resources`` list, or an
     ``api`` domain has an empty/absent ``requests`` list.
   - Structured OSCAL/manifest metadata fields (``metadata.title``,
     ``metadata.props``, the pre-``Notes:`` header of ``metadata.remarks``,
     ``control-implementations[].description``/``props``, or
     ``implemented-requirements[].description``/``props``) contain
     ``NotImplemented``, ``TODO``, ``STUB``, ``placeholder``, or
     ``always passes`` (case-insensitive). Free-text ``Notes:`` prose in
     ``metadata.remarks`` is excluded from general keyword matching so
     explanatory remarks do not trigger false positives.
   - Any Rego policy body has fewer than 3 meaningful rule lines.

3. **Downward-only ``.stub-baseline`` ratchet & POAM linkage**:
   - Every stub manifest must be referenced by at least one POAM entry across
     ``docs/POAM.md`` or the regional POAM registers
     (``docs/compliance/{us_fed,eu_ecb,apac_mas,universal}/POAM_*.md``).
   - ``compliance/lula/.stub-baseline`` is a **downward-only** ratchet: adding
     new stub manifests is forbidden. ``--update-baseline`` may only lower (or
     preserve) ``.stub-baseline`` as stubs are hardened into real assertions;
     it refuses (exit 1) if ``stub_count > baseline``.

Usage::

    # In CI — fails on corpus-floor breach, upward stub drift, or missing POAM
    uv run python scripts/check_lula_stub_count.py

    # After hardening a stub into real assertions (ratchets baseline downward):
    uv run python scripts/check_lula_stub_count.py --update-baseline
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, NamedTuple

try:
    import yaml
except ImportError:
    print(
        "ERROR: PyYAML is required. Install with: pip install pyyaml",
        file=sys.stderr,
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Default paths & floors (relative to repo root)
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[1]
_LULA_DIR = _REPO_ROOT / "compliance" / "lula"
_BASELINE_FILE = _LULA_DIR / ".stub-baseline"
_MANIFEST_GLOB = "lula-validation-*.yaml"
_LIVE_CORPUS_MIN_MANIFESTS = 30
_LIVE_CORPUS_MIN_REGO_BODIES = 30

_DEFAULT_RELATIVE_POAM_FILES: tuple[Path, ...] = (
    Path("docs/POAM.md"),
    Path("docs/compliance/us_fed/POAM_US_FED.md"),
    Path("docs/compliance/eu_ecb/POAM_EU_ECB.md"),
    Path("docs/compliance/apac_mas/POAM_APAC_MAS.md"),
    Path("docs/compliance/universal/POAM_ISO42001.md"),
)

# ---------------------------------------------------------------------------
# Stub detection patterns
# ---------------------------------------------------------------------------

# Rego lines that are NOT meaningful rules (comments, blank lines, package
# declarations, import statements, and trivial default lines).
_REGO_NOISE_RE = re.compile(
    r"^\s*("
    r"#.*"  # comment
    r"|package\s+\w+"  # package declaration
    r"|import\s+.*"  # import statement
    r"|default\s+allow\s*=\s*true"  # allow-all stub default
    r"|default\s+validate\s*=\s*false"  # common default
    r"|)\s*$"  # blank line
)

# Structured metadata stub markers (case-insensitive).
_STUB_MARKERS: tuple[str, ...] = (
    "NotImplemented",
    "TODO",
    "STUB",
    "placeholder",
    "always passes",
)

_POAM_ID_TOKEN = r"(?:POAM|AI600|EU|APAC|MAS|ISO)-[\w-]+"
_POAM_HEADING_RE = re.compile(
    rf"^###\s+({_POAM_ID_TOKEN})\b[^\n]*$",
    re.MULTILINE,
)
_ANY_HEADING_RE = re.compile(r"^#{1,3}\s+", re.MULTILINE)
_POAM_TABLE_ROW_RE = re.compile(
    rf"^\s*\|\s*\*?\*?({_POAM_ID_TOKEN})\*?\*?\s*\|(.*)$",
    re.MULTILINE,
)
_MANIFEST_NAME_RE = re.compile(r"lula-validation-[\w-]+\.yaml")


class ManifestResult(NamedTuple):
    name: str
    is_stub: bool
    stub_reasons: list[str]
    has_poam: bool
    poam_ids: list[str]
    rego_body_count: int = 0
    domain_count: int = 0
    structural_errors: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# OSCAL + standalone payload extraction
# ---------------------------------------------------------------------------


def _rego_meaningful_line_count(rego_text: str) -> int:
    """Count non-noise lines in a Rego policy body."""
    return sum(1 for line in rego_text.splitlines() if not _REGO_NOISE_RE.match(line))


def _extract_lula_payloads(
    doc: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Extract Lula ``domain``/``provider`` payload dicts and any parse errors.

    Supports both:
    - OSCAL ``component-definition.back-matter.resources[].description`` YAML blocks
    - Standalone top-level ``domain`` / ``provider`` mappings
    """
    payloads: list[dict[str, Any]] = []
    errors: list[str] = []

    if "domain" in doc or "provider" in doc:
        payloads.append(doc)

    comp_def = doc.get("component-definition")
    if isinstance(comp_def, dict):
        back_matter = comp_def.get("back-matter")
        if isinstance(back_matter, dict):
            resources = back_matter.get("resources")
            if isinstance(resources, list):
                for idx, resource in enumerate(resources):
                    if not isinstance(resource, dict):
                        continue
                    desc = resource.get("description")
                    if not isinstance(desc, str) or not desc.strip():
                        continue
                    try:
                        embedded = yaml.safe_load(desc)
                    except yaml.YAMLError as exc:
                        errors.append(
                            f"back-matter.resources[{idx}].description YAML error: {exc}"
                        )
                        continue
                    if isinstance(embedded, dict) and (
                        "domain" in embedded or "provider" in embedded
                    ):
                        payloads.append(embedded)

    return payloads, errors


def _extract_domains(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Return all ``domain`` mappings found in standalone or OSCAL payloads."""
    domains: list[dict[str, Any]] = []
    payloads, _ = _extract_lula_payloads(doc)
    for payload in payloads:
        domain = payload.get("domain")
        if isinstance(domain, dict) and domain:
            domains.append(domain)
    return domains


def _extract_rego_bodies(doc: dict[str, Any]) -> list[str]:
    """Return all non-empty Rego policy bodies found in standalone or OSCAL payloads."""
    bodies: list[str] = []
    payloads, _ = _extract_lula_payloads(doc)
    for payload in payloads:
        provider = payload.get("provider")
        if not isinstance(provider, dict):
            continue
        opa_spec = provider.get("opa-spec") or provider.get("opa") or {}
        if isinstance(opa_spec, dict):
            rego = opa_spec.get("rego") or opa_spec.get("policy")
            if isinstance(rego, str) and rego.strip():
                bodies.append(rego)
    return bodies


def _has_empty_resources(doc: dict[str, Any]) -> bool:
    """Return True if any extracted domain has an empty or absent resource/request list."""
    domains = _extract_domains(doc)
    if not domains:
        return True

    for domain in domains:
        domain_type = domain.get("type", "")
        if domain_type == "kubernetes":
            k8s_spec = domain.get("kubernetes-spec") or domain.get("kubernetes")
            if not isinstance(k8s_spec, dict):
                return True
            resources = k8s_spec.get("resources")
            if not isinstance(resources, list) or len(resources) == 0:
                return True
        elif domain_type == "api":
            api_spec = domain.get("api-spec") or domain.get("api")
            if not isinstance(api_spec, dict):
                return True
            requests = api_spec.get("requests")
            if not isinstance(requests, list) or len(requests) == 0:
                return True

    return False


def _collect_props_strings(props: Any) -> list[str]:
    """Extract name/value strings from an OSCAL ``props`` list."""
    out: list[str] = []
    if not isinstance(props, list):
        return out
    for item in props:
        if isinstance(item, dict):
            for key in ("name", "value"):
                val = item.get(key)
                if val is not None:
                    out.append(str(val))
    return out


def _strip_notes_block(remarks: str) -> str:
    """Return only the structured header before any ``Notes:`` free-text prose."""
    return re.split(r"(?:^|\n)\s*Notes\s*:", remarks, maxsplit=1)[0]


def _has_stub_markers_in_doc(doc: dict[str, Any]) -> list[str]:
    """Return stub markers found in structured OSCAL or standalone metadata fields.

    Free-text ``Notes:`` blocks inside ``metadata.remarks`` are excluded from
    general keyword matching so manifests that explain historical stub migration
    (e.g., ``"non-stub value"`` or ``"deprecated Rego stub confusion"``) are not
    falsely flagged. Explicit ``"always passes"`` assertions are matched across
    all remarks and structured descriptions.
    """
    candidates: list[str] = []
    full_remarks_blocks: list[str] = []

    # Standalone top-level metadata & description
    metadata = doc.get("metadata")
    if isinstance(metadata, dict):
        for key in ("name", "title"):
            val = metadata.get(key)
            if val:
                candidates.append(str(val))
        for map_key in ("annotations", "labels"):
            mapping = metadata.get(map_key)
            if isinstance(mapping, dict):
                candidates.extend(str(v) for v in mapping.values())
        candidates.extend(_collect_props_strings(metadata.get("props")))
        remarks = metadata.get("remarks")
        if isinstance(remarks, str) and remarks:
            candidates.append(_strip_notes_block(remarks))
            full_remarks_blocks.append(remarks)

    description = doc.get("description")
    if description:
        candidates.append(str(description))

    # OSCAL component-definition structured fields
    comp_def = doc.get("component-definition")
    if isinstance(comp_def, dict):
        cd_meta = comp_def.get("metadata")
        if isinstance(cd_meta, dict):
            title = cd_meta.get("title")
            if title:
                candidates.append(str(title))
            candidates.extend(_collect_props_strings(cd_meta.get("props")))
            cd_remarks = cd_meta.get("remarks")
            if isinstance(cd_remarks, str) and cd_remarks:
                candidates.append(_strip_notes_block(cd_remarks))
                full_remarks_blocks.append(cd_remarks)

        components = comp_def.get("components")
        if isinstance(components, list):
            for comp in components:
                if not isinstance(comp, dict):
                    continue
                candidates.extend(_collect_props_strings(comp.get("props")))
                ctrl_impls = comp.get("control-implementations")
                if not isinstance(ctrl_impls, list):
                    continue
                for ci in ctrl_impls:
                    if not isinstance(ci, dict):
                        continue
                    ci_desc = ci.get("description")
                    if ci_desc:
                        candidates.append(str(ci_desc))
                    candidates.extend(_collect_props_strings(ci.get("props")))
                    impl_reqs = ci.get("implemented-requirements")
                    if not isinstance(impl_reqs, list):
                        continue
                    for ir in impl_reqs:
                        if not isinstance(ir, dict):
                            continue
                        ir_desc = ir.get("description")
                        if ir_desc:
                            candidates.append(str(ir_desc))
                        candidates.extend(_collect_props_strings(ir.get("props")))
                        ir_remarks = ir.get("remarks")
                        if isinstance(ir_remarks, str) and ir_remarks:
                            candidates.append(_strip_notes_block(ir_remarks))
                            full_remarks_blocks.append(ir_remarks)

    combined = " ".join(candidates).lower()
    found: list[str] = []
    for marker in _STUB_MARKERS:
        if marker.lower() in combined:
            found.append(marker)

    if "always passes" not in found:
        full_remarks_lower = " ".join(full_remarks_blocks).lower()
        if "always passes" in full_remarks_lower:
            found.append("always passes")

    return found


def classify_manifest(path: Path) -> ManifestResult:
    """Classify a single Lula manifest as stub or active, failing closed on vacuous structure."""
    raw_text = path.read_text(encoding="utf-8")
    stub_reasons: list[str] = []
    structural_errors: list[str] = []

    try:
        doc = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        msg = f"YAML parse error: {exc}"
        return ManifestResult(
            name=path.name,
            is_stub=True,
            stub_reasons=[msg],
            has_poam=False,
            poam_ids=[],
            rego_body_count=0,
            domain_count=0,
            structural_errors=(msg,),
        )

    if not isinstance(doc, dict):
        msg = "document is not a YAML mapping"
        return ManifestResult(
            name=path.name,
            is_stub=True,
            stub_reasons=[msg],
            has_poam=False,
            poam_ids=[],
            rego_body_count=0,
            domain_count=0,
            structural_errors=(msg,),
        )

    _, payload_errors = _extract_lula_payloads(doc)
    structural_errors.extend(payload_errors)
    stub_reasons.extend(payload_errors)

    domains = _extract_domains(doc)
    if not domains:
        msg = (
            "no domain mapping extracted from back-matter.resources[].description "
            "or top-level domain"
        )
        structural_errors.append(msg)
        stub_reasons.append(msg)

    rego_bodies = _extract_rego_bodies(doc)
    if not rego_bodies:
        msg = (
            "no Rego policy body extracted from back-matter.resources[].description "
            "or provider"
        )
        structural_errors.append(msg)
        stub_reasons.append(msg)

    # Check 1 & 4: Rego allow-all default or fewer than 3 meaningful rule lines
    for rego in rego_bodies:
        if re.search(r"\bdefault\s+allow\s*=\s*true\b", rego):
            stub_reasons.append("Rego contains 'default allow = true' (allow-all stub)")
        meaningful = _rego_meaningful_line_count(rego)
        if meaningful < 3:
            stub_reasons.append(
                f"Rego has only {meaningful} meaningful rule line(s) "
                f"(threshold: 3) — policy body is effectively empty"
            )

    # Check 2: empty or absent resources/requests list in extracted domain(s)
    if domains and _has_empty_resources(doc):
        stub_reasons.append(
            "domain resources/requests list is empty or absent "
            "(no target resources to validate)"
        )

    # Check 3: stub markers in structured OSCAL/manifest fields (excluding Notes: prose)
    markers = _has_stub_markers_in_doc(doc)
    if markers:
        stub_reasons.append(
            f"structured metadata/OSCAL fields contain stub marker(s): {', '.join(markers)}"
        )

    seen: set[str] = set()
    unique_reasons: list[str] = []
    for reason in stub_reasons:
        if reason not in seen:
            seen.add(reason)
            unique_reasons.append(reason)

    return ManifestResult(
        name=path.name,
        is_stub=bool(unique_reasons),
        stub_reasons=unique_reasons,
        has_poam=False,
        poam_ids=[],
        rego_body_count=len(rego_bodies),
        domain_count=len(domains),
        structural_errors=tuple(structural_errors),
    )


# ---------------------------------------------------------------------------
# POAM coverage
# ---------------------------------------------------------------------------


def _record_poam_mentions(
    manifest_to_poam: dict[str, list[str]],
    poam_id: str,
    text_block: str,
) -> None:
    for match in _MANIFEST_NAME_RE.finditer(text_block):
        fname = match.group(0)
        ids = manifest_to_poam.setdefault(fname, [])
        if poam_id not in ids:
            ids.append(poam_id)


def _load_poam_references(
    poam_paths: Path | Sequence[Path],
) -> dict[str, list[str]]:
    """Parse central and regional POAM Markdown files for Lula manifest references.

    Recognises both:
    - ``### <ID>`` Markdown sections (bounded at the next ``#``/``##``/``###`` heading)
    - Markdown table rows (``| <ID> | ... |``)
    """
    paths: Sequence[Path] = (
        [poam_paths] if isinstance(poam_paths, Path) else list(poam_paths)
    )
    manifest_to_poam: dict[str, list[str]] = {}

    for poam_path in paths:
        if not poam_path.exists():
            continue
        text = poam_path.read_text(encoding="utf-8")

        # 1. ### <ID> sections (bounded at the next heading so trailing summary
        # tables are never attributed to the preceding entry).
        for heading_match in _POAM_HEADING_RE.finditer(text):
            poam_id = heading_match.group(1)
            body_start = heading_match.end()
            next_heading = _ANY_HEADING_RE.search(text, pos=body_start)
            body_end = next_heading.start() if next_heading else len(text)
            _record_poam_mentions(manifest_to_poam, poam_id, text[body_start:body_end])

        # 2. Markdown table rows: | <ID> | ... |
        for row_match in _POAM_TABLE_ROW_RE.finditer(text):
            poam_id = row_match.group(1)
            row_tail = row_match.group(2)
            _record_poam_mentions(manifest_to_poam, poam_id, row_tail)

    return manifest_to_poam


def check_poam_coverage(
    results: list[ManifestResult],
    poam_refs: dict[str, list[str]],
) -> list[ManifestResult]:
    """Annotate each stub result with its POAM coverage."""
    updated: list[ManifestResult] = []
    for r in results:
        if r.is_stub:
            ids = list(poam_refs.get(r.name, []))
            updated.append(
                ManifestResult(
                    name=r.name,
                    is_stub=r.is_stub,
                    stub_reasons=r.stub_reasons,
                    has_poam=bool(ids),
                    poam_ids=ids,
                    rego_body_count=r.rego_body_count,
                    domain_count=r.domain_count,
                    structural_errors=r.structural_errors,
                )
            )
        else:
            updated.append(r)
    return updated


# ---------------------------------------------------------------------------
# Baseline I/O
# ---------------------------------------------------------------------------


def _read_baseline(baseline_file: Path = _BASELINE_FILE) -> int | None:
    """Read the stub count baseline. Returns None if missing or malformed."""
    if not baseline_file.exists():
        return None
    try:
        value = int(baseline_file.read_text(encoding="utf-8").strip())
    except ValueError:
        return None
    return value if value >= 0 else None


def _write_baseline(count: int, baseline_file: Path = _BASELINE_FILE) -> None:
    """Write the stub count baseline."""
    baseline_file.write_text(f"{count}\n", encoding="utf-8")


def _display_path(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


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
        print(
            f"{r.name:<{_COL_NAME}} {stub_label:<{_COL_STUB}} {poam_label:<{_COL_POAM}}"
        )
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
            print(
                "    ✗ NO POAM ENTRY — reference this manifest in docs/POAM.md or "
                "regional POAM_*.md"
            )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "CI gate: enforce non-vacuous OSCAL Lula Rego extraction, POAM linkage, "
            "and downward-only ratcheting on compliance/lula/.stub-baseline "
            "(new stub manifests are forbidden)."
        )
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help=(
            "Ratchet compliance/lula/.stub-baseline downward (or keep unchanged) "
            "after hardening stubs into real assertions. Refuses (exit 1) if "
            "current stub count exceeds the existing baseline."
        ),
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Repository root directory (default: parent of scripts/).",
    )
    parser.add_argument(
        "--lula-dir",
        type=Path,
        default=None,
        help="Directory containing lula-validation-*.yaml manifests.",
    )
    parser.add_argument(
        "--baseline-file",
        type=Path,
        default=None,
        help="Path to .stub-baseline file (default: <lula-dir>/.stub-baseline).",
    )
    parser.add_argument(
        "--poam-files",
        type=Path,
        nargs="+",
        default=None,
        help="Explicit POAM Markdown file(s) to scan for manifest references.",
    )
    parser.add_argument(
        "--min-manifests",
        type=int,
        default=None,
        help=(
            f"Minimum required lula-validation-*.yaml files "
            f"(default: {_LIVE_CORPUS_MIN_MANIFESTS} on live repo scan, 1 on custom --lula-dir)."
        ),
    )
    parser.add_argument(
        "--min-rego-bodies",
        type=int,
        default=None,
        help=(
            f"Minimum required extracted Rego policy bodies across the corpus "
            f"(default: {_LIVE_CORPUS_MIN_REGO_BODIES} on live repo scan, 1 on custom --lula-dir)."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    is_custom_corpus = args.repo_root is not None or args.lula_dir is not None
    repo_root = (args.repo_root or _REPO_ROOT).resolve()
    lula_dir = (
        args.lula_dir.resolve()
        if args.lula_dir is not None
        else (repo_root / "compliance" / "lula")
    )
    baseline_file = (
        args.baseline_file.resolve()
        if args.baseline_file is not None
        else (lula_dir / ".stub-baseline")
    )
    poam_files: list[Path] = (
        [p.resolve() for p in args.poam_files]
        if args.poam_files is not None
        else [repo_root / rel for rel in _DEFAULT_RELATIVE_POAM_FILES]
    )
    min_manifests = (
        args.min_manifests
        if args.min_manifests is not None
        else (1 if is_custom_corpus else _LIVE_CORPUS_MIN_MANIFESTS)
    )
    min_rego_bodies = (
        args.min_rego_bodies
        if args.min_rego_bodies is not None
        else (1 if is_custom_corpus else _LIVE_CORPUS_MIN_REGO_BODIES)
    )

    # ------------------------------------------------------------------
    # 1. Discover lula-validation-*.yaml manifests
    # ------------------------------------------------------------------
    yaml_files = sorted(lula_dir.glob(_MANIFEST_GLOB)) if lula_dir.is_dir() else []
    if not yaml_files:
        print(
            f"ERROR: no {_MANIFEST_GLOB} files found in {_display_path(lula_dir, repo_root)}",
            file=sys.stderr,
        )
        return 1

    results = [classify_manifest(f) for f in yaml_files]

    # ------------------------------------------------------------------
    # 2. Check POAM coverage
    # ------------------------------------------------------------------
    poam_refs = _load_poam_references(poam_files)
    results = check_poam_coverage(results, poam_refs)

    total_manifests = len(results)
    total_rego_bodies = sum(r.rego_body_count for r in results)
    structural_bad = [r for r in results if r.structural_errors]
    stubs = [r for r in results if r.is_stub]
    stub_count = len(stubs)
    stubs_without_poam = [r for r in stubs if not r.has_poam]

    # ------------------------------------------------------------------
    # 3. Print summary table
    # ------------------------------------------------------------------
    print("\n=== Lula Stub Count Gate ===")
    print(
        f"Scanned {total_manifests} manifest(s) in {_display_path(lula_dir, repo_root)} "
        f"(extracted {total_rego_bodies} Rego policy body/bodies)"
    )
    print(f"Stubs found: {stub_count}\n")
    _print_table(results)
    _print_stub_details(results)

    # ------------------------------------------------------------------
    # 4. Evaluate non-vacuous corpus & per-manifest floors first
    # ------------------------------------------------------------------
    failures: list[str] = []

    if total_manifests < min_manifests:
        failures.append(
            f"Corpus manifest count {total_manifests} is below required floor "
            f"{min_manifests} in {_display_path(lula_dir, repo_root)} "
            f"(non-vacuous recognition check failed)."
        )

    if total_rego_bodies < min_rego_bodies:
        failures.append(
            f"Total extracted Rego bodies {total_rego_bodies} is below required floor "
            f"{min_rego_bodies} across {total_manifests} manifest(s) "
            f"(vacuous parser / schema drift check failed)."
        )

    for bad in structural_bad:
        joined = "; ".join(bad.structural_errors)
        failures.append(
            f"Manifest {bad.name} failed non-vacuous OSCAL/Lula extraction: {joined}"
        )

    baseline = _read_baseline(baseline_file)
    baseline_disp = _display_path(baseline_file, repo_root)

    # ------------------------------------------------------------------
    # 5. --update-baseline mode (DOWNWARD-ONLY RATCHET)
    # ------------------------------------------------------------------
    if args.update_baseline:
        if baseline is not None and stub_count > baseline:
            failures.append(
                f"Refusing --update-baseline: current stub count {stub_count} > "
                f"existing baseline {baseline} in {baseline_disp}.\n"
                f"  .stub-baseline is a downward-only ratchet; adding new stub "
                f"manifests is forbidden. Implement real fail-closed Rego assertions."
            )
        if stubs_without_poam:
            names = ", ".join(r.name for r in stubs_without_poam)
            failures.append(
                f"Stub(s) without POAM entry: {names}\n"
                f"  Reference each stub manifest in docs/POAM.md or regional POAM_*.md."
            )
        if failures:
            print("\n=== LULA STUB GATE FAILED ===", file=sys.stderr)
            for i, msg in enumerate(failures, 1):
                print(f"\n[{i}] {msg}", file=sys.stderr)
            return 1

        _write_baseline(stub_count, baseline_file)
        print(f"\n✓ Baseline ratcheted: {baseline_disp} ← {stub_count}")
        return 0

    # ------------------------------------------------------------------
    # 6. Normal verification mode
    # ------------------------------------------------------------------
    if baseline is None:
        failures.append(
            f"Baseline file missing or invalid: {baseline_disp}\n"
            f"  Restore {baseline_disp} from version control."
        )
    elif stub_count > baseline:
        failures.append(
            f"Stub count EXCEEDED downward-only baseline: {stub_count} > "
            f"baseline {baseline} ({baseline_disp})\n"
            f"  Adding new stub Lula manifests is forbidden (.stub-baseline is a "
            f"downward-only ratchet). Replace placeholder logic with fail-closed "
            f"OPA Rego assertions."
        )
    else:
        print(f"\nBaseline: {baseline}  Current: {stub_count}  ✓ within baseline")

    if stubs_without_poam:
        names = ", ".join(r.name for r in stubs_without_poam)
        failures.append(
            f"Stub(s) without POAM entry: {names}\n"
            f"  Fix: Ensure each existing stub manifest is referenced in docs/POAM.md "
            f"or docs/compliance/*/POAM_*.md."
        )

    if failures:
        print("\n=== LULA STUB GATE FAILED ===", file=sys.stderr)
        for i, msg in enumerate(failures, 1):
            print(f"\n[{i}] {msg}", file=sys.stderr)
        return 1

    print("\n✓ Lula stub gate passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
