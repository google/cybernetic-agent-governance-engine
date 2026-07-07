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
Tests for NeMo Guardrails CBRN Colang rail — AI 600-1 §2.6 (POAM AI600-007).

These tests validate the *static content* of the Colang rail file
(src/gateway/governance/nemo/colang/cbrn_rails.co) without requiring a live
NeMo Guardrails runtime.  The rail file is parsed as plain text and its
structural elements are verified.

Validates:
- Rail file exists at the expected path
- All 15 CBRN phrases are declared in the ``user ask cbrn synthesis`` block
- ``bot refuse cbrn`` response block is present
- ``cbrn safety check`` flow is defined and references both user and bot blocks
- Region guard comment is present (CAGE_DEPLOYMENT_REGION=US_FED)
- POAM reference AI600-007 is present
- Phase 3 / Cat-M annotation is present
"""

from __future__ import annotations

import pathlib
import re

import pytest

# ---------------------------------------------------------------------------
# Rail file path
# ---------------------------------------------------------------------------

RAIL_FILE = pathlib.Path("src/gateway/governance/nemo/colang/cbrn_rails.co")

# ---------------------------------------------------------------------------
# Expected content constants
# ---------------------------------------------------------------------------

EXPECTED_CBRN_PHRASES = [
    "synthesize nerve agent",
    "weaponize pathogen",
    "enrich uranium",
    "dirty bomb construction",
    "ricin synthesis",
    "VX precursor",
    "sarin production",
    "anthrax spore",
    "smallpox culture",
    "radiological dispersal",
    "biological weapon",
    "chemical weapon synthesis",
    "nuclear device construction",
    "improvised explosive device",
    "CBRN attack",
]

EXPECTED_USER_BLOCK = "define user ask cbrn synthesis"
EXPECTED_BOT_BLOCK = "define bot refuse cbrn"
EXPECTED_FLOW_BLOCK = "define flow cbrn safety check"
EXPECTED_REGION_GUARD = "CAGE_DEPLOYMENT_REGION=US_FED"
EXPECTED_POAM_REF = "AI600-007"
EXPECTED_PHASE_ANNOTATION = "Phase"
EXPECTED_CAT_M_ANNOTATION = "Cat-M"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rail_content() -> str:
    """Load the CBRN Colang rail file content."""
    assert RAIL_FILE.exists(), (
        f"CBRN rail file not found at {RAIL_FILE}. "
        "Run Phase 3 §7.1 implementation first."
    )
    return RAIL_FILE.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# File existence
# ---------------------------------------------------------------------------


class TestCBRNRailFileExists:
    """Verify the CBRN rail file exists at the expected path."""

    def test_rail_file_exists(self):
        """cbrn_rails.co must exist at src/gateway/governance/nemo/colang/."""
        assert RAIL_FILE.exists(), f"CBRN rail file missing: {RAIL_FILE}"

    def test_rail_file_is_not_empty(self, rail_content: str):
        """cbrn_rails.co must not be empty."""
        assert len(rail_content.strip()) > 0, "CBRN rail file is empty"

    def test_rail_file_extension(self):
        """Rail file must have .co extension (Colang format)."""
        assert RAIL_FILE.suffix == ".co", (
            f"Expected .co extension, got {RAIL_FILE.suffix}"
        )


# ---------------------------------------------------------------------------
# Structural blocks
# ---------------------------------------------------------------------------


class TestCBRNRailStructure:
    """Verify the structural Colang blocks are present."""

    def test_user_block_defined(self, rail_content: str):
        """``define user ask cbrn synthesis`` block must be present."""
        assert EXPECTED_USER_BLOCK in rail_content, (
            f"Missing Colang block: {EXPECTED_USER_BLOCK!r}"
        )

    def test_bot_block_defined(self, rail_content: str):
        """``define bot refuse cbrn`` block must be present."""
        assert EXPECTED_BOT_BLOCK in rail_content, (
            f"Missing Colang block: {EXPECTED_BOT_BLOCK!r}"
        )

    def test_flow_block_defined(self, rail_content: str):
        """``define flow cbrn safety check`` block must be present."""
        assert EXPECTED_FLOW_BLOCK in rail_content, (
            f"Missing Colang block: {EXPECTED_FLOW_BLOCK!r}"
        )

    def test_flow_references_user_intent(self, rail_content: str):
        """The flow block must reference ``user ask cbrn synthesis``."""
        assert "user ask cbrn synthesis" in rail_content, (
            "Flow block does not reference 'user ask cbrn synthesis'"
        )

    def test_flow_references_bot_response(self, rail_content: str):
        """The flow block must reference ``bot refuse cbrn``."""
        assert "bot refuse cbrn" in rail_content, (
            "Flow block does not reference 'bot refuse cbrn'"
        )

    def test_bot_response_is_non_empty(self, rail_content: str):
        """The bot refuse response must contain a non-empty string."""
        # Extract content after "define bot refuse cbrn"
        match = re.search(
            r'define bot refuse cbrn\s+"([^"]+)"',
            rail_content,
        )
        assert match is not None, (
            "Could not find a quoted response string in 'define bot refuse cbrn' block"
        )
        response_text = match.group(1).strip()
        assert len(response_text) > 0, "Bot refuse response is empty"


# ---------------------------------------------------------------------------
# CBRN phrase coverage
# ---------------------------------------------------------------------------


class TestCBRNPhraseCoverage:
    """Verify all 15 CBRN phrases are declared in the user intent block."""

    @pytest.mark.parametrize("phrase", EXPECTED_CBRN_PHRASES)
    def test_phrase_present_in_rail(self, phrase: str, rail_content: str):
        """Each CBRN phrase must appear in the rail file."""
        assert phrase in rail_content, f"CBRN phrase missing from rail file: {phrase!r}"

    def test_phrase_count(self, rail_content: str):
        """Rail file must contain all 15 expected CBRN phrases."""
        found = [p for p in EXPECTED_CBRN_PHRASES if p in rail_content]
        assert len(found) == len(EXPECTED_CBRN_PHRASES), (
            f"Expected {len(EXPECTED_CBRN_PHRASES)} CBRN phrases, "
            f"found {len(found)}: missing {set(EXPECTED_CBRN_PHRASES) - set(found)}"
        )


# ---------------------------------------------------------------------------
# Compliance annotations
# ---------------------------------------------------------------------------


class TestCBRNRailComplianceAnnotations:
    """Verify compliance metadata comments are present in the rail file."""

    def test_region_guard_comment(self, rail_content: str):
        """Rail file must declare CAGE_DEPLOYMENT_REGION=US_FED guard."""
        assert EXPECTED_REGION_GUARD in rail_content, (
            f"Missing region guard comment: {EXPECTED_REGION_GUARD!r}"
        )

    def test_poam_reference(self, rail_content: str):
        """Rail file must reference POAM item AI600-007."""
        assert EXPECTED_POAM_REF in rail_content, (
            f"Missing POAM reference: {EXPECTED_POAM_REF!r}"
        )

    def test_phase_annotation(self, rail_content: str):
        """Rail file must include a Phase annotation."""
        assert EXPECTED_PHASE_ANNOTATION in rail_content, (
            "Missing Phase annotation in rail file"
        )

    def test_cat_m_annotation(self, rail_content: str):
        """Rail file must include Cat-M annotation (AO pre-approval required)."""
        assert EXPECTED_CAT_M_ANNOTATION in rail_content, (
            "Missing Cat-M annotation — AO pre-approval requirement not documented"
        )

    def test_ai600_section_reference(self, rail_content: str):
        """Rail file must reference AI 600-1 §2.6."""
        assert "AI 600-1" in rail_content, (
            "Missing AI 600-1 regulatory reference in rail file"
        )
