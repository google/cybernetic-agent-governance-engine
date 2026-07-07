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
Architecture Guardrail Tests — Decoupled Governance Abstraction
===============================================================

These tests are PERMANENT pipeline checks, not one-off validations.
They enforce the structural boundary between business logic and regulatory
citation strings, ensuring Option 3 (Decoupled Governance Abstraction) is
never silently reverted by a future code change.

Key invariants enforced:
  1. No hardcoded regulatory strings in .py execution code paths.
  2. ControlRegistry loads and resolves all CTRL_* IDs correctly.
  3. GovernanceControl enum members exist for every key in control_mappings.json.
  4. Legacy citations are accessible via the registry (SIEM compatibility).
"""

import json
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC_GOVERNANCE = _REPO_ROOT / "src" / "gateway" / "governance"
_CONTROL_MAPPINGS = _REPO_ROOT / "config" / "control_mappings.json"
_COMPLIANCE_DIR = _REPO_ROOT / "config" / "compliance"
# Region-specific controls: only present in specific regional profiles.
# Key = CTRL_* value, Value = region code where it is defined.
_REGION_SPECIFIC_CONTROLS = {
    "CTRL_FRIA_006": "EU_ECB",  # EU AI Act Art. 29a FRIA — EU-only statutory requirement
}

# ---------------------------------------------------------------------------
# Prohibited patterns — match regulatory CITATION STRINGS in executable code.
# Crucially, these must NOT match:
#   - OTel attribute keys: "iso42001.control", "iso42001.tier", etc.
#     These are fixed wire-format identifiers, not volatile regulatory citations.
#   - Pydantic field names or OTel span attribute constants.
# The patterns below match only the human-readable citation form (with space).
_PROHIBITED_PATTERNS = [
    # "SR 26-2" or "SR26-2" as a regulatory reference
    re.compile(r"\bSR\s*26-2\b", re.IGNORECASE),
    # "SR 11-7" or "SR11-7" as a regulatory reference
    re.compile(r"\bSR\s*11-7\b", re.IGNORECASE),
    # "ISO 42001" with a space — the human-readable citation form.
    # Does NOT match "iso42001.control" (no space before the dot).
    re.compile(r"\bISO\s+42001\b", re.IGNORECASE),
    # "DORA Art." citation form
    re.compile(r"\bDORA\s+Art\b", re.IGNORECASE),
]

# Files intentionally excluded from the scan:
#   constants.py      — the registry itself; owns all citation strings by design
#   iso_control.py    — OTel telemetry infrastructure; "iso42001.*" are wire-format
#                       attribute keys, not regulatory citation strings
#   oscal_ssp_exporter.py — OSCAL/compliance export layer; framework-aware by design
_EXCLUDED_FILES = {"constants.py", "iso_control.py", "oscal_ssp_exporter.py"}


def _executable_lines(path: Path):
    """Yield (line_number, stripped_execution_code) for executable non-documentation lines.

    Skips:
    - Lines that are entirely Python comments (# ...)
    - Lines that are entirely docstring content (inside triple-quoted strings)
    - Blank lines

    Rationale: regulatory strings in docstrings and comments are narrative
    documentation, not business logic coupling.  Only execution-path strings
    (f-strings, string literals passed to functions, attribute values, etc.)
    create the coupling risk this test guards against.
    """
    with open(path, encoding="utf-8") as fh:
        content = fh.read()

    # Strip all triple-quoted docstring blocks before line-by-line analysis.
    # This removes both single-line and multi-line docstrings.
    import ast

    try:
        tree = ast.parse(content)
        docstring_lines: set[int] = set()
        for node in ast.walk(tree):
            # Module, class, and function docstrings are the first Expr(Constant) child
            if isinstance(
                node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                if (
                    node.body
                    and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)
                ):
                    doc_node = node.body[0]
                    for lineno in range(
                        doc_node.lineno, (doc_node.end_lineno or doc_node.lineno) + 1
                    ):
                        docstring_lines.add(lineno)
    except SyntaxError:
        docstring_lines = set()

    for line_num, raw_line in enumerate(content.splitlines(), 1):
        if line_num in docstring_lines:
            continue
        # Strip inline comments; keep only the executable portion.
        code_part = raw_line.split("#")[0].strip()
        if code_part:
            yield line_num, code_part


# ---------------------------------------------------------------------------
# Test 1 — No hardcoded regulatory strings in src/gateway/governance/*.py
# ---------------------------------------------------------------------------


def test_enforce_no_hardcoded_regulatory_strings_in_governance_src():
    """Architecture Guardrail: regulatory citation strings must not appear in
    executable governance source code.

    All framework citations (SR 26-2, ISO 42001, DORA, etc.) must live
    exclusively in config/control_mappings.json.  Python source files may
    only reference stable GovernanceControl enum members (CTRL_* IDs).

    If this test fails, move the offending string to control_mappings.json
    and reference it via ControlRegistry.get_mapping(GovernanceControl.<ID>).
    """
    violations = []

    for python_file in sorted(_SRC_GOVERNANCE.glob("**/*.py")):
        if python_file.name in _EXCLUDED_FILES:
            continue

        for line_num, code in _executable_lines(python_file):
            for pattern in _PROHIBITED_PATTERNS:
                if pattern.search(code):
                    violations.append(
                        f"{python_file.relative_to(_REPO_ROOT)}:{line_num} "
                        f"— hardcoded citation detected: {code!r}"
                    )

    assert not violations, (
        "Architecture violation(s) detected — hardcoded regulatory strings found "
        "in executable governance source code.\n\n"
        "Move each citation to config/control_mappings.json and reference it via "
        "ControlRegistry.get_mapping(GovernanceControl.<ID>):\n\n"
        + "\n".join(violations)
    )


# ---------------------------------------------------------------------------
# Test 2 — control_mappings.json is valid and contains all required keys
# ---------------------------------------------------------------------------


def test_control_mappings_json_is_valid():
    """control_mappings.json must exist, be valid JSON, and have required fields."""
    assert _CONTROL_MAPPINGS.exists(), (
        f"config/control_mappings.json not found at {_CONTROL_MAPPINGS}"
    )

    with open(_CONTROL_MAPPINGS) as fh:
        raw = json.load(fh)

    required_fields = {
        "internal_id",
        "primary_framework",
        "co_frameworks",
        "legacy_citation",
        "scope",
        "description",
    }

    for ctrl_id, mapping in raw.items():
        if ctrl_id.startswith("_"):
            continue  # skip meta-keys

        missing = required_fields - set(mapping.keys())
        assert not missing, (
            f"control_mappings.json entry '{ctrl_id}' is missing required fields: {missing}"
        )
        assert mapping["scope"] in ("agentic", "traditional_ml"), (
            f"'{ctrl_id}' has invalid scope '{mapping['scope']}'. "
            f"Must be 'agentic' or 'traditional_ml'."
        )


# ---------------------------------------------------------------------------
# Test 3 — GovernanceControl enum covers all CTRL_* keys in the registry
# ---------------------------------------------------------------------------


def test_governance_control_enum_covers_all_registry_keys():
    """Every CTRL_* key across all regional compliance profiles must have a
    GovernanceControl member, and vice versa.

    Prevents orphaned registry entries that no code can reference, and ensures
    the enum is the canonical authority for all control IDs globally.

    Region-specific controls (e.g. CTRL_FRIA_006 only in EU_ECB) are allowed
    to be absent from some regional profiles, but must be present in at least
    one profile and always have a GovernanceControl enum member.
    """
    from src.gateway.governance.constants import GovernanceControl

    enum_values = {member.value for member in GovernanceControl}

    # Collect all CTRL_* keys across all regional profiles
    all_registry_keys: set[str] = set()
    profile_files = list(_COMPLIANCE_DIR.glob("*_BASELINE.json"))
    assert profile_files, (
        f"No regional compliance profiles found in {_COMPLIANCE_DIR}. "
        f"Expected at least one *_BASELINE.json file."
    )
    for profile_path in profile_files:
        with open(profile_path) as fh:
            raw = json.load(fh)
        for k in raw:
            if not k.startswith("_"):
                all_registry_keys.add(k)

    # Also include keys from the legacy fallback file for backward compat
    if _CONTROL_MAPPINGS.exists():
        with open(_CONTROL_MAPPINGS) as fh:
            legacy_raw = json.load(fh)
        for k in legacy_raw:
            if not k.startswith("_"):
                all_registry_keys.add(k)

    orphaned = all_registry_keys - enum_values
    assert not orphaned, (
        f"Orphaned control keys in regional profiles with no GovernanceControl member: "
        f"{orphaned}. Add the missing Enum entries to constants.py."
    )

    unmapped = enum_values - all_registry_keys
    assert not unmapped, (
        f"GovernanceControl members with no entry in any regional profile: "
        f"{unmapped}. Add entries to at least one config/compliance/*_BASELINE.json."
    )


# ---------------------------------------------------------------------------
# Test 4 — ControlRegistry resolves all controls and exposes legacy citations
# ---------------------------------------------------------------------------


def test_control_registry_resolves_all_controls_with_legacy_citation():
    """ControlRegistry must resolve every GovernanceControl and provide a
    non-empty legacy_citation for SIEM backward-compatibility.

    Region-specific controls (e.g. CTRL_FRIA_006) are tested against the
    regional profile where they are defined, and verified to be absent
    (via get_mapping_safe) in all other regions.
    """
    from src.gateway.governance.constants import (
        ControlRegistry,
        GovernanceControl,
    )

    # Test all controls against the default US_FED region first
    ControlRegistry.reconfigure("US_FED")
    registry = ControlRegistry()

    for control in GovernanceControl:
        ctrl_id = control.value
        if ctrl_id in _REGION_SPECIFIC_CONTROLS:
            # Region-specific: must be ABSENT in US_FED
            meta = registry.get_mapping_safe(control)
            assert meta is None, (
                f"Region-specific control {ctrl_id} should be absent in US_FED profile "
                f"but get_mapping_safe() returned a value: {meta}"
            )
        else:
            meta = registry.get_mapping(control)
            assert meta.get("legacy_citation"), (
                f"Control {ctrl_id} has an empty legacy_citation in the US_FED profile. "
                f"SIEM consumers require this field."
            )
            assert meta.get("primary_framework"), (
                f"Control {ctrl_id} has an empty primary_framework in US_FED."
            )

    # Now verify each region-specific control is PRESENT in its designated region
    for ctrl_id, designated_region in _REGION_SPECIFIC_CONTROLS.items():
        ControlRegistry.reconfigure(designated_region)
        region_registry = ControlRegistry()
        ctrl_enum = next(c for c in GovernanceControl if c.value == ctrl_id)
        meta = region_registry.get_mapping_safe(ctrl_enum)
        assert meta is not None, (
            f"Region-specific control {ctrl_id} should be PRESENT in the "
            f"{designated_region} profile but get_mapping_safe() returned None."
        )
        assert meta.get("legacy_citation"), (
            f"Control {ctrl_id} in {designated_region} profile has empty legacy_citation."
        )

    # Restore to US_FED for any subsequent tests
    ControlRegistry.reconfigure("US_FED")


# ---------------------------------------------------------------------------
# Test 5 — No orphaned GovernanceControl enum members (no dead CTRL_* IDs)
# ---------------------------------------------------------------------------


def test_ensure_all_enum_controls_are_referenced_in_source():
    """Guarantees no orphaned controls exist in the internal control registry.

    A GovernanceControl member is considered "active" if either:
      - Its .name attribute (e.g. TRADITIONAL_MRM_VALIDATION) appears in src/
        governance code — covering GovernanceControl.<NAME> enum accesses.
      - Its .value string (e.g. CTRL_MRM_004) appears in src/ governance code
        — covering log prefixes, OTel attributes, and violation message strings.

    Both signals are checked so that a control wired only via OTel log strings
    (not imported by name) is still considered active.

    If this test fails, the failing control must be wired into at least one
    governance check in src/gateway/governance/ before it can remain in the enum.
    """
    from src.gateway.governance.constants import GovernanceControl

    # Build combined source of all governance .py files except constants.py
    combined_source = ""
    for python_file in sorted(_SRC_GOVERNANCE.glob("**/*.py")):
        if python_file.name == "constants.py":
            continue
        with open(python_file, encoding="utf-8") as fh:
            combined_source += fh.read()

    orphaned = []
    for control in GovernanceControl:
        name_present = (
            control.name in combined_source
        )  # e.g. TRADITIONAL_MRM_VALIDATION
        value_present = control.value in combined_source  # e.g. CTRL_MRM_004
        if not (name_present or value_present):
            orphaned.append(
                f"  {control.name!r} ({control.value!r}) — "
                f"no reference found in src/gateway/governance/**/*.py"
            )

    assert not orphaned, (
        "Orphaned GovernanceControl member(s) detected — defined in constants.py "
        "but not referenced in any governance execution code:\n\n"
        + "\n".join(orphaned)
        + "\n\nWire each control into an active check before merging."
    )
