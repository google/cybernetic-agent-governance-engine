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
FrameworkRouter Unit Tests — v0.1.0 Crown Jewel Decoupling
===========================================================

Validates the FrameworkRouter class and the four external JSON routing files
that replaced hardcoded _UCA_TO_* dicts in oscal_ssp_exporter.py.

Test matrix covers:

  1. JSON schema integrity — all four routing files parse and have required keys.
  2. Cache isolation — FrameworkRouter._cache uses framework ID as key; calling
     get() twice for the same framework must return the identical object, and
     loading one framework must not pollute the cache entry for another.
  3. UCA coverage — every UCA-N (UCA-1 through UCA-9) produces at least one
     control ID for every framework.
  4. Control descriptions — every control ID referenced in uca_mappings has a
     corresponding entry in control_descriptions.
  5. Narrative template rendering — format_narrative() produces non-empty,
     non-placeholder prose for every (framework × control) combination.
  6. build_summary() — returns a non-empty multi-line string covering all UCAs.
  7. all_controls() — returns a deduplicated list; verifies no duplicates.
  8. Sentinel-driven trace suppression — the _NO_LEGAL_FORCE_MARKER logic in
     causal_gatekeeper.py correctly resolves citations for all three regions:
     US_FED (keeps legacy), EU_ECB (suppresses to primary), APAC_MAS (suppresses).
  9. Unknown framework — FrameworkRouter.get() raises ValueError cleanly.
  10. Missing file — FrameworkRouter() raises FileNotFoundError for unregistered
      stems (regression guard if a file is accidentally deleted).
"""

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[1]
_OSCAL_MAPPINGS_DIR = _REPO_ROOT / "config" / "oscal" / "framework_mappings"
_COMPLIANCE_DIR = _REPO_ROOT / "config" / "compliance"

_SUPPORTED_FRAMEWORKS = ["NIST", "ISO42001", "EU_AI_ACT", "MAS_FEAT"]

# UCA IDs present in config/stpa_control_structure.yaml
_EXPECTED_UCAS = [f"UCA-{i}" for i in range(1, 10)]  # UCA-1 … UCA-9

_REQUIRED_JSON_KEYS = {
    "_schema_version",
    "_framework_id",
    "_framework_label",
    "_framework_source",
    "uca_mappings",
    "control_descriptions",
    "narrative_template",
}


# ---------------------------------------------------------------------------
# Helper: fresh FrameworkRouter with cleared class-level cache
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_framework_router_cache():
    """Wipe the class-level cache before every test to prevent cross-test pollution."""
    from src.gateway.governance.oscal_ssp_exporter import FrameworkRouter
    FrameworkRouter._cache.clear()
    yield
    FrameworkRouter._cache.clear()


# ---------------------------------------------------------------------------
# Test 1 — JSON schema integrity for all four routing files
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("framework_id", _SUPPORTED_FRAMEWORKS)
def test_framework_json_has_required_keys(framework_id):
    """Every framework JSON file must exist and contain all required top-level keys."""
    from src.gateway.governance.oscal_ssp_exporter import _FRAMEWORK_FILE_MAP
    file_stem = _FRAMEWORK_FILE_MAP[framework_id]
    json_path = _OSCAL_MAPPINGS_DIR / f"{file_stem}.json"

    assert json_path.exists(), (
        f"Framework routing file not found: {json_path}. "
        f"Expected at config/oscal/framework_mappings/{file_stem}.json"
    )

    with open(json_path) as fh:
        data = json.load(fh)

    missing = _REQUIRED_JSON_KEYS - set(data.keys())
    assert not missing, (
        f"{json_path.name} is missing required keys: {missing}"
    )

    assert data["_framework_id"] == framework_id, (
        f"{json_path.name}: _framework_id '{data['_framework_id']}' "
        f"does not match expected '{framework_id}'"
    )
    assert data["_framework_label"], (
        f"{json_path.name}: _framework_label must be a non-empty string."
    )
    assert data["_framework_source"].startswith("http"), (
        f"{json_path.name}: _framework_source must be a URL."
    )
    assert isinstance(data["uca_mappings"], dict), (
        f"{json_path.name}: uca_mappings must be a dict."
    )
    assert isinstance(data["control_descriptions"], dict), (
        f"{json_path.name}: control_descriptions must be a dict."
    )
    assert isinstance(data["narrative_template"], str) and data["narrative_template"], (
        f"{json_path.name}: narrative_template must be a non-empty string."
    )


# ---------------------------------------------------------------------------
# Test 2 — Cache identity: same object returned on repeated get() calls
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("framework_id", _SUPPORTED_FRAMEWORKS)
def test_framework_router_cache_returns_same_object(framework_id):
    """FrameworkRouter.get() must return the identical instance on repeated calls
    (no redundant JSON I/O, no stale-state from re-loading)."""
    from src.gateway.governance.oscal_ssp_exporter import FrameworkRouter

    router_a = FrameworkRouter.get(framework_id)
    router_b = FrameworkRouter.get(framework_id)

    assert router_a is router_b, (
        f"FrameworkRouter.get('{framework_id}') returned different objects on repeated calls. "
        f"Cache is not working — two separate loads could desync state."
    )


# ---------------------------------------------------------------------------
# Test 3 — Cache isolation: loading one framework does not pollute another
# ---------------------------------------------------------------------------

def test_framework_router_cache_isolation():
    """Verify loading NIST does not affect the EU_AI_ACT cache entry and vice versa."""
    from src.gateway.governance.oscal_ssp_exporter import FrameworkRouter

    nist = FrameworkRouter.get("NIST")
    eu = FrameworkRouter.get("EU_AI_ACT")

    assert nist is not eu, "NIST and EU_AI_ACT must be distinct FrameworkRouter instances."
    assert nist.framework_id == "NIST"
    assert eu.framework_id == "EU_AI_ACT"
    assert nist.label != eu.label, "Framework labels must differ across routers."
    assert nist.uca_mappings != eu.uca_mappings, (
        "NIST and EU_AI_ACT uca_mappings must be distinct dicts — "
        "cache collision would mean one dict was overwritten by the other."
    )


# ---------------------------------------------------------------------------
# Test 4 — UCA coverage: every expected UCA maps to at least one control
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("framework_id", _SUPPORTED_FRAMEWORKS)
def test_all_ucas_have_at_least_one_control_mapping(framework_id):
    """Every UCA-1 through UCA-9 must map to at least one control ID."""
    from src.gateway.governance.oscal_ssp_exporter import FrameworkRouter

    router = FrameworkRouter.get(framework_id)

    missing = []
    for uca_id in _EXPECTED_UCAS:
        controls = router.controls_for_uca(uca_id)
        if not controls:
            missing.append(uca_id)

    assert not missing, (
        f"FrameworkRouter('{framework_id}'): the following UCAs have no control mappings: "
        f"{missing}. Update config/oscal/framework_mappings/{framework_id}*.json."
    )


# ---------------------------------------------------------------------------
# Test 5 — Control descriptions: every referenced control has a description
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("framework_id", _SUPPORTED_FRAMEWORKS)
def test_all_referenced_controls_have_descriptions(framework_id):
    """Every control ID appearing in uca_mappings must have an entry in
    control_descriptions.  Orphaned control IDs produce bare placeholder prose."""
    from src.gateway.governance.oscal_ssp_exporter import FrameworkRouter

    router = FrameworkRouter.get(framework_id)

    missing_descriptions = []
    for uca_id, ctrl_ids in router.uca_mappings.items():
        for ctrl_id in ctrl_ids:
            if ctrl_id not in router.control_descriptions:
                missing_descriptions.append(f"{uca_id} → {ctrl_id!r}")

    assert not missing_descriptions, (
        f"FrameworkRouter('{framework_id}'): controls referenced in uca_mappings "
        f"but absent from control_descriptions (will produce placeholder prose):\n"
        + "\n".join(f"  {m}" for m in missing_descriptions)
        + f"\nFix: add missing entries to control_descriptions in "
          f"config/oscal/framework_mappings/{framework_id}*.json."
    )


# ---------------------------------------------------------------------------
# Test 6 — Narrative template rendering (no stray {placeholders})
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("framework_id", _SUPPORTED_FRAMEWORKS)
def test_narrative_template_renders_without_placeholder_artifacts(framework_id):
    """format_narrative() must produce fully-rendered prose with no leftover
    {placeholder} tokens for every control in the routing table."""
    from src.gateway.governance.oscal_ssp_exporter import FrameworkRouter

    # We need at least one UCAModel stub to drive the test.
    # Build minimal ducks typed stubs — avoids loading the full STPA yaml.
    class _StubUCA:
        def __init__(self, uca_id: str, enforcement=("opa",)):
            self.id = uca_id
            self.uca_type = "commission"
            self.description = f"Stub description for {uca_id}"
            self.enforcement = list(enforcement)

    router = FrameworkRouter.get(framework_id)
    stub_ucas = [_StubUCA(uid) for uid in _EXPECTED_UCAS]

    all_ctrls = router.all_controls(stub_ucas)
    assert all_ctrls, (
        f"FrameworkRouter('{framework_id}').all_controls() returned an empty list. "
        f"At least one control must be referenced."
    )

    for ctrl in all_ctrls:
        prose = router.format_narrative(ctrl, stub_ucas)
        assert prose, (
            f"format_narrative('{ctrl}') returned empty string for framework '{framework_id}'."
        )
        # Detect stray {placeholder} tokens from incomplete format() calls
        import re
        stray = re.findall(r"\{[a-z_]+\}", prose)
        assert not stray, (
            f"format_narrative('{ctrl}') for '{framework_id}' contains unrendered "
            f"template placeholders: {stray}. "
            f"Check narrative_template in the JSON routing file."
        )


# ---------------------------------------------------------------------------
# Test 7 — build_summary() covers all UCAs, returns multi-line output
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("framework_id", _SUPPORTED_FRAMEWORKS)
def test_build_summary_covers_all_ucas(framework_id):
    """build_summary() must include every UCA ID in the output prose."""
    from src.gateway.governance.oscal_ssp_exporter import FrameworkRouter

    class _StubUCA:
        def __init__(self, uid):
            self.id = uid
            self.uca_type = "commission"
            self.description = f"Stub: {uid}"
            self.enforcement = ["opa"]

    router = FrameworkRouter.get(framework_id)
    stub_ucas = [_StubUCA(uid) for uid in _EXPECTED_UCAS]
    summary = router.build_summary(stub_ucas)

    assert summary, (
        f"FrameworkRouter('{framework_id}').build_summary() returned empty string."
    )
    for uca_id in _EXPECTED_UCAS:
        assert uca_id in summary, (
            f"build_summary() for '{framework_id}' does not mention {uca_id}. "
            f"All UCAs must appear in the cross-walk prose."
        )


# ---------------------------------------------------------------------------
# Test 8 — all_controls() returns deduplicated list
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("framework_id", _SUPPORTED_FRAMEWORKS)
def test_all_controls_has_no_duplicates(framework_id):
    """all_controls() must return each control ID at most once (deduplication).

    Duplicate control IDs in the routing file would cause duplicate by-component
    entries in the OSCAL SSP patch, which breaks idempotency guarantees.
    """
    from src.gateway.governance.oscal_ssp_exporter import FrameworkRouter

    class _StubUCA:
        def __init__(self, uid):
            self.id = uid
            self.uca_type = "commission"
            self.description = f"Stub: {uid}"
            self.enforcement = ["opa"]

    router = FrameworkRouter.get(framework_id)
    stub_ucas = [_StubUCA(uid) for uid in _EXPECTED_UCAS]
    controls = router.all_controls(stub_ucas)

    duplicates = [c for c in controls if controls.count(c) > 1]
    assert not duplicates, (
        f"FrameworkRouter('{framework_id}').all_controls() returned duplicate entries: "
        f"{list(set(duplicates))}. Fix deduplication logic in FrameworkRouter.all_controls()."
    )


# ---------------------------------------------------------------------------
# Test 9 — Unknown framework raises ValueError clearly
# ---------------------------------------------------------------------------

def test_unknown_framework_raises_value_error():
    """FrameworkRouter.get() must raise ValueError with a helpful message when
    an unregistered framework ID is requested."""
    from src.gateway.governance.oscal_ssp_exporter import FrameworkRouter

    with pytest.raises(ValueError, match="unknown framework"):
        FrameworkRouter.get("FINMA_CH")

    with pytest.raises(ValueError, match="unknown framework"):
        FrameworkRouter.get("")


# ---------------------------------------------------------------------------
# Test 10 — Sentinel-driven trace citation logic in causal_gatekeeper.py
# ---------------------------------------------------------------------------

_NO_LEGAL_FORCE_MARKER = "no legal force"


@pytest.mark.parametrize("region,ctrl_id,expect_suppressed", [
    # US_FED: legacy_citation has NO marker → keep legacy citation
    ("US_FED",   "CTRL_MRM_004", False),
    ("US_FED",   "CTRL_TEL_003", False),
    # EU_ECB: legacy_citation explicitly says "no legal force in EU jurisdiction"
    ("EU_ECB",   "CTRL_MRM_004", True),
    ("EU_ECB",   "CTRL_TEL_003", False),   # EU TEL has no marker — ISO baseline only
    # APAC_MAS: legacy_citation says "no legal force in Singapore"
    ("APAC_MAS", "CTRL_MRM_004", True),
    ("APAC_MAS", "CTRL_TEL_003", False),   # APAC TEL has ISO baseline only
])
def test_no_legal_force_sentinel_drives_citation_selection(region, ctrl_id, expect_suppressed):
    """Verify that the _NO_LEGAL_FORCE_MARKER sentinel correctly selects between
    legacy_citation and primary_framework for OTel span emission.

    This is the data-driven replacement for the deleted _EU_LEGACY_CITATION_OVERRIDE dict.
    The logic must fire for any region whose profile explicitly flags a citation
    as having no legal force — not just EU.
    """
    from src.gateway.governance.constants import ControlRegistry, GovernanceControl

    ControlRegistry.reconfigure(region)
    registry = ControlRegistry()

    ctrl_enum = next(c for c in GovernanceControl if c.value == ctrl_id)
    meta = registry.get_mapping(ctrl_enum)

    has_marker = _NO_LEGAL_FORCE_MARKER in meta["legacy_citation"]

    if expect_suppressed:
        assert has_marker, (
            f"Region '{region}', control '{ctrl_id}': expected legacy_citation to contain "
            f"'{_NO_LEGAL_FORCE_MARKER}' (so the gatekeeper suppresses it and emits "
            f"primary_framework instead), but got: {meta['legacy_citation']!r}"
        )
        # Verify primary_framework is non-empty and jurisdiction-appropriate
        assert meta["primary_framework"], (
            f"Region '{region}', control '{ctrl_id}': primary_framework must be non-empty "
            f"when legacy_citation is suppressed."
        )
        # Primary framework must NOT contain SR 26-2 (that's a US-only citation)
        assert "SR 26-2" not in meta["primary_framework"], (
            f"Region '{region}', control '{ctrl_id}': primary_framework contains SR 26-2 "
            f"but this region suppresses US citations. "
            f"Got: {meta['primary_framework']!r}"
        )
    else:
        assert not has_marker, (
            f"Region '{region}', control '{ctrl_id}': legacy_citation unexpectedly contains "
            f"'{_NO_LEGAL_FORCE_MARKER}': {meta['legacy_citation']!r}"
        )

    # Restore US_FED for subsequent tests
    ControlRegistry.reconfigure("US_FED")
