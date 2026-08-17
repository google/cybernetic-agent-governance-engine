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
tests/infrastructure/test_data_residency_us_fed.py
==================================================
US_FED data-residency and configuration gate tests.

These tests assert that:
- config/thresholds/US_FED_BASELINE.json exists and contains the expected
  jurisdiction and region markers.
- config/compliance/US_FED_BASELINE.json exists, is valid JSON, and contains
  at least one control definition.
- config/thresholds/ directory contains US_FED_BASELINE.json.
- config/oscal/framework_mappings/NIST_SP800_53.json exists and is non-empty.
- The US_FED thresholds file has correct CBF, drawdown, STPA, and consensus
  configuration values.

These tests run in CI (marked ``local``) without any live services.

Marks
-----
- ``us_fed`` : US_FED region-specific test
- ``local``  : safe to run with no live services (CI default)
"""

from __future__ import annotations

import json
import os
import pathlib

import pytest

# ---------------------------------------------------------------------------
# Region-aware skip guard (mirrors the EU_ECB pattern in test_data_residency.py)
# ---------------------------------------------------------------------------

_REGION = os.environ.get("CAGE_DEPLOYMENT_REGION", "")

_SKIP_NON_US_FED = pytest.mark.skipif(
    _REGION not in ("US_FED", ""),
    reason=(
        f"US_FED data-residency tests skipped for region {_REGION!r}. "
        "Set CAGE_DEPLOYMENT_REGION=US_FED (or leave unset) to run."
    ),
)

# Paths under test
_THRESHOLDS_DIR = pathlib.Path("config/thresholds")
_US_FED_THRESHOLDS = _THRESHOLDS_DIR / "US_FED_BASELINE.json"
_US_FED_COMPLIANCE = pathlib.Path("config/compliance/US_FED_BASELINE.json")
_NIST_MAPPING = pathlib.Path("config/oscal/framework_mappings/NIST_SP800_53.json")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _load_json(path: pathlib.Path) -> dict:
    """Load and parse a JSON file; skip if not found."""
    if not path.exists():
        pytest.skip(f"{path} not found — skipping test")
    return json.loads(path.read_text())


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------


@pytest.mark.us_fed
@pytest.mark.local
@_SKIP_NON_US_FED
class TestUSFEDDataResidency:
    """Gate tests for US_FED configuration and data-residency compliance."""

    # ------------------------------------------------------------------
    # 1. Thresholds baseline
    # ------------------------------------------------------------------

    def test_us_fed_thresholds_file_exists(self) -> None:
        """config/thresholds/US_FED_BASELINE.json must exist."""
        assert _US_FED_THRESHOLDS.exists(), (
            f"{_US_FED_THRESHOLDS} not found. "
            "US_FED baseline thresholds file is required."
        )

    def test_us_fed_thresholds_has_region_marker(self) -> None:
        """US_FED_BASELINE.json must declare cage_deployment_region=US_FED."""
        data = _load_json(_US_FED_THRESHOLDS)
        assert "cage_deployment_region" in data or "_region" in data, (
            "US_FED_BASELINE.json must contain a region marker key "
            "(cage_deployment_region or _region)"
        )
        region = data.get("cage_deployment_region") or data.get("_region")
        assert region == "US_FED", (
            f"Expected region='US_FED' in US_FED_BASELINE.json, got {region!r}"
        )

    def test_us_fed_thresholds_jurisdiction_field(self) -> None:
        """US_FED_BASELINE.json must declare jurisdiction=US_FED."""
        data = _load_json(_US_FED_THRESHOLDS)
        assert "jurisdiction" in data, (
            "US_FED_BASELINE.json must contain a 'jurisdiction' field"
        )
        assert data["jurisdiction"] == "US_FED", (
            f"Expected jurisdiction='US_FED', got {data['jurisdiction']!r}"
        )

    def test_us_fed_thresholds_cbf_section(self) -> None:
        """US_FED_BASELINE.json must have a cbf section with min_cash_balance."""
        data = _load_json(_US_FED_THRESHOLDS)
        assert "cbf" in data, "US_FED_BASELINE.json must contain a 'cbf' section"
        cbf = data["cbf"]
        assert "min_cash_balance" in cbf, "cbf section must contain 'min_cash_balance'"
        assert isinstance(cbf["min_cash_balance"], (int, float)), (
            "cbf.min_cash_balance must be numeric"
        )
        assert cbf["min_cash_balance"] > 0, (
            f"cbf.min_cash_balance must be positive, got {cbf['min_cash_balance']}"
        )

    def test_us_fed_thresholds_stpa_section(self) -> None:
        """US_FED_BASELINE.json must have a stpa section with UCA-2 and UCA-5 thresholds."""
        data = _load_json(_US_FED_THRESHOLDS)
        assert "stpa" in data, "US_FED_BASELINE.json must contain an 'stpa' section"
        stpa = data["stpa"]
        assert "uca5_drawdown_threshold_pct" in stpa, (
            "stpa section must contain 'uca5_drawdown_threshold_pct'"
        )
        assert "max_latency_ms" in stpa, "stpa section must contain 'max_latency_ms'"
        # UCA-5 drawdown threshold must be a positive percentage
        assert stpa["uca5_drawdown_threshold_pct"] > 0, (
            "stpa.uca5_drawdown_threshold_pct must be positive"
        )
        # Latency threshold must be positive
        assert stpa["max_latency_ms"] > 0, "stpa.max_latency_ms must be positive"

    def test_us_fed_thresholds_consensus_section(self) -> None:
        """US_FED_BASELINE.json must have a consensus section with threshold_usd."""
        data = _load_json(_US_FED_THRESHOLDS)
        assert "consensus" in data, (
            "US_FED_BASELINE.json must contain a 'consensus' section"
        )
        consensus = data["consensus"]
        assert "threshold_usd" in consensus, (
            "consensus section must contain 'threshold_usd'"
        )
        assert isinstance(consensus["threshold_usd"], (int, float)), (
            "consensus.threshold_usd must be numeric"
        )

    def test_us_fed_thresholds_tier1_keywords_present(self) -> None:
        """US_FED_BASELINE.json must include tier1_keywords for prompt injection detection."""
        data = _load_json(_US_FED_THRESHOLDS)
        assert "tier1_keywords" in data, (
            "US_FED_BASELINE.json must contain 'tier1_keywords'"
        )
        keywords = data["tier1_keywords"]
        assert isinstance(keywords, list), "tier1_keywords must be a list"
        assert len(keywords) >= 3, (
            f"tier1_keywords must have at least 3 entries, got {len(keywords)}"
        )

    # ------------------------------------------------------------------
    # 2. Compliance baseline
    # ------------------------------------------------------------------

    def test_us_fed_compliance_baseline_exists(self) -> None:
        """config/compliance/US_FED_BASELINE.json must exist."""
        assert _US_FED_COMPLIANCE.exists(), (
            f"{_US_FED_COMPLIANCE} not found. "
            "US_FED compliance baseline file is required."
        )

    def test_us_fed_compliance_baseline_is_valid_json(self) -> None:
        """config/compliance/US_FED_BASELINE.json must be valid JSON."""
        data = _load_json(_US_FED_COMPLIANCE)
        assert isinstance(data, dict), (
            "US_FED_BASELINE.json (compliance) must parse to a dict"
        )

    def test_us_fed_compliance_baseline_has_controls(self) -> None:
        """config/compliance/US_FED_BASELINE.json must contain at least one control."""
        data = _load_json(_US_FED_COMPLIANCE)
        # Controls are dict keys starting with CTRL_
        control_keys = [k for k in data.keys() if k.startswith("CTRL_")]
        assert len(control_keys) >= 1, (
            f"US_FED compliance baseline must contain at least one CTRL_ key, "
            f"found keys: {list(data.keys())}"
        )

    def test_us_fed_compliance_baseline_region_marker(self) -> None:
        """config/compliance/US_FED_BASELINE.json must declare _region=US_FED."""
        data = _load_json(_US_FED_COMPLIANCE)
        assert "_region" in data, (
            "US_FED_BASELINE.json (compliance) must contain a '_region' field"
        )
        assert data["_region"] == "US_FED", (
            f"Expected _region='US_FED', got {data['_region']!r}"
        )

    def test_us_fed_compliance_controls_have_primary_framework(self) -> None:
        """Each CTRL_ entry must declare a primary_framework field."""
        data = _load_json(_US_FED_COMPLIANCE)
        control_keys = [k for k in data.keys() if k.startswith("CTRL_")]
        for ctrl_key in control_keys:
            ctrl = data[ctrl_key]
            assert isinstance(ctrl, dict), (
                f"Control {ctrl_key!r} must be a dict, got {type(ctrl)}"
            )
            assert "primary_framework" in ctrl, (
                f"Control {ctrl_key!r} must have a 'primary_framework' field"
            )
            assert ctrl["primary_framework"], (
                f"Control {ctrl_key!r} primary_framework must be non-empty"
            )

    # ------------------------------------------------------------------
    # 3. Thresholds directory completeness
    # ------------------------------------------------------------------

    def test_thresholds_directory_contains_us_fed_baseline(self) -> None:
        """config/thresholds/ must include US_FED_BASELINE.json."""
        assert _THRESHOLDS_DIR.exists(), f"{_THRESHOLDS_DIR} directory does not exist"
        baseline_files = [
            f.name for f in _THRESHOLDS_DIR.iterdir() if f.suffix == ".json"
        ]
        assert "US_FED_BASELINE.json" in baseline_files, (
            f"config/thresholds/ must contain US_FED_BASELINE.json. "
            f"Found: {baseline_files}"
        )

    def test_thresholds_directory_has_all_three_regions(self) -> None:
        """config/thresholds/ must contain baseline files for all three regions."""
        assert _THRESHOLDS_DIR.exists(), f"{_THRESHOLDS_DIR} directory does not exist"
        json_files = {f.name for f in _THRESHOLDS_DIR.iterdir() if f.suffix == ".json"}
        for expected in (
            "US_FED_BASELINE.json",
            "EU_ECB_BASELINE.json",
            "APAC_MAS_BASELINE.json",
        ):
            assert expected in json_files, (
                f"config/thresholds/ must contain {expected}. Found: {json_files}"
            )

    # ------------------------------------------------------------------
    # 4. NIST SP 800-53 framework mapping
    # ------------------------------------------------------------------

    def test_nist_sp800_53_mapping_exists(self) -> None:
        """config/oscal/framework_mappings/NIST_SP800_53.json must exist."""
        assert _NIST_MAPPING.exists(), (
            f"{_NIST_MAPPING} not found. "
            "NIST SP 800-53 OSCAL mapping file is required for US_FED posture."
        )

    def test_nist_sp800_53_mapping_is_nonempty(self) -> None:
        """NIST_SP800_53.json must be non-empty valid JSON with UCA mappings."""
        data = _load_json(_NIST_MAPPING)
        assert data, "NIST_SP800_53.json must not be an empty dict"
        assert "uca_mappings" in data, (
            "NIST_SP800_53.json must contain a 'uca_mappings' section"
        )
        uca_mappings = data["uca_mappings"]
        assert isinstance(uca_mappings, dict), "uca_mappings must be a dict"
        assert len(uca_mappings) >= 1, (
            f"uca_mappings must have at least one UCA entry, got {len(uca_mappings)}"
        )

    def test_nist_sp800_53_mapping_has_framework_metadata(self) -> None:
        """NIST_SP800_53.json must contain framework identification metadata."""
        data = _load_json(_NIST_MAPPING)
        assert "_framework_id" in data, (
            "NIST_SP800_53.json must contain '_framework_id'"
        )
        assert data["_framework_id"] == "NIST", (
            f"Expected _framework_id='NIST', got {data['_framework_id']!r}"
        )
        assert "_framework_label" in data, (
            "NIST_SP800_53.json must contain '_framework_label'"
        )

    def test_nist_sp800_53_uca4_maps_to_controls(self) -> None:
        """UCA-4 must map to at least one NIST control in the framework mapping."""
        data = _load_json(_NIST_MAPPING)
        uca_mappings = data.get("uca_mappings", {})
        assert "UCA-4" in uca_mappings, (
            "uca_mappings must contain an entry for UCA-4 "
            "(execute_trade atomic failure — key US_FED control)"
        )
        controls = uca_mappings["UCA-4"]
        assert isinstance(controls, list), "UCA-4 mapping must be a list of control IDs"
        assert len(controls) >= 1, (
            f"UCA-4 must map to at least one NIST control, got {controls}"
        )
