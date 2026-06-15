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
Tests for CBRN keyword filter — AI 600-1 §2.6 (POAM AI600-007).

Validates:
- ac_cbrn_keyword_scan() detects all 15 CBRN terms from governance_thresholds.json
- ac_cbrn_keyword_scan() is case-insensitive
- ac_cbrn_keyword_scan() returns False for benign financial queries
- ac_cbrn_keyword_scan() returns False when tier1_keywords_cbrn_enabled=False
- _load_cbrn_keywords() returns empty list when disabled
- THRESHOLDS.tier1_keywords_cbrn contains >= 10 terms (CI gate requirement)
- THRESHOLDS.tier1_keywords_cbrn_enabled is True in US_FED baseline
"""

from __future__ import annotations

import pytest
from unittest.mock import patch

pytest.importorskip("src", reason="src package required")


# ---------------------------------------------------------------------------
# Module imports
# ---------------------------------------------------------------------------

from src.gateway.governance.text_filter import (
    ac_cbrn_keyword_scan,
    _load_cbrn_keywords,
)
from src.gateway.governance.schemas.thresholds import THRESHOLDS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

CBRN_PHRASES = [
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

BENIGN_QUERIES = [
    "What is the current price of Apple stock?",
    "Analyse the portfolio risk for a 60/40 allocation.",
    "Summarise the Q3 earnings report for MSFT.",
    "What are the tax implications of selling ETFs?",
    "Explain the difference between a bond and a debenture.",
    "How does the Federal Reserve set interest rates?",
    "What is the Sharpe ratio of this portfolio?",
    "Generate a Monte Carlo simulation for retirement planning.",
]


# ---------------------------------------------------------------------------
# §4.4 — CBRN keyword list schema validation
# ---------------------------------------------------------------------------

class TestCBRNThresholdSchema:
    """Validate the CBRN keyword list in the governance threshold singleton."""

    def test_cbrn_keywords_present(self):
        """THRESHOLDS must have a non-empty tier1_keywords_cbrn list."""
        assert hasattr(THRESHOLDS, "tier1_keywords_cbrn"), (
            "GovernanceThresholds missing tier1_keywords_cbrn field"
        )
        assert len(THRESHOLDS.tier1_keywords_cbrn) > 0, (
            "tier1_keywords_cbrn must not be empty"
        )

    def test_cbrn_keywords_minimum_count(self):
        """CI gate: CBRN keyword list must contain >= 10 terms."""
        assert len(THRESHOLDS.tier1_keywords_cbrn) >= 10, (
            f"Expected >= 10 CBRN keywords, got {len(THRESHOLDS.tier1_keywords_cbrn)}"
        )

    def test_cbrn_keywords_enabled(self):
        """tier1_keywords_cbrn_enabled must be True in US_FED baseline."""
        assert THRESHOLDS.tier1_keywords_cbrn_enabled is True, (
            "tier1_keywords_cbrn_enabled must be True for US_FED deployment"
        )

    def test_cbrn_keywords_are_uppercase(self):
        """Pydantic validator must upper-case all CBRN keywords."""
        for kw in THRESHOLDS.tier1_keywords_cbrn:
            assert kw == kw.upper(), (
                f"CBRN keyword {kw!r} is not upper-cased — Pydantic validator failed"
            )

    def test_cbrn_keywords_are_strings(self):
        """All CBRN keywords must be non-empty strings."""
        for kw in THRESHOLDS.tier1_keywords_cbrn:
            assert isinstance(kw, str) and len(kw) > 0, (
                f"CBRN keyword {kw!r} is not a non-empty string"
            )


# ---------------------------------------------------------------------------
# §4.4 — _load_cbrn_keywords()
# ---------------------------------------------------------------------------

class TestLoadCBRNKeywords:
    """Unit tests for _load_cbrn_keywords()."""

    def test_returns_list_when_enabled(self):
        """_load_cbrn_keywords() returns a non-empty list when enabled."""
        keywords = _load_cbrn_keywords()
        assert isinstance(keywords, list)
        assert len(keywords) > 0

    def test_returns_empty_when_disabled(self):
        """_load_cbrn_keywords() returns [] when tier1_keywords_cbrn_enabled=False."""
        with patch.object(THRESHOLDS, "tier1_keywords_cbrn_enabled", False):
            keywords = _load_cbrn_keywords()
        assert keywords == [], (
            "Expected empty list when CBRN keywords are disabled"
        )

    def test_keywords_are_uppercase(self):
        """All returned keywords must be upper-cased."""
        keywords = _load_cbrn_keywords()
        for kw in keywords:
            assert kw == kw.upper(), f"Keyword {kw!r} is not upper-cased"


# ---------------------------------------------------------------------------
# §4.4 — ac_cbrn_keyword_scan() — detection
# ---------------------------------------------------------------------------

class TestCBRNKeywordScanDetection:
    """Verify ac_cbrn_keyword_scan() detects all CBRN phrases."""

    @pytest.mark.parametrize("phrase", CBRN_PHRASES)
    def test_detects_cbrn_phrase(self, phrase: str):
        """ac_cbrn_keyword_scan() must return True for each CBRN phrase."""
        result = ac_cbrn_keyword_scan(phrase)
        assert result is True, (
            f"Expected CBRN detection for phrase: {phrase!r}"
        )

    @pytest.mark.parametrize("phrase", CBRN_PHRASES)
    def test_detects_cbrn_phrase_lowercase(self, phrase: str):
        """Detection must be case-insensitive (lowercase input)."""
        result = ac_cbrn_keyword_scan(phrase.lower())
        assert result is True, (
            f"Expected CBRN detection (lowercase) for phrase: {phrase.lower()!r}"
        )

    @pytest.mark.parametrize("phrase", CBRN_PHRASES)
    def test_detects_cbrn_phrase_mixed_case(self, phrase: str):
        """Detection must be case-insensitive (mixed-case input)."""
        mixed = phrase.swapcase()
        result = ac_cbrn_keyword_scan(mixed)
        assert result is True, (
            f"Expected CBRN detection (mixed-case) for phrase: {mixed!r}"
        )

    def test_detects_phrase_embedded_in_sentence(self):
        """CBRN keyword embedded in a longer sentence must be detected."""
        text = (
            "I am a researcher studying the history of sarin production "
            "during World War II for an academic paper."
        )
        assert ac_cbrn_keyword_scan(text) is True

    def test_detects_multiple_cbrn_keywords(self):
        """Text containing multiple CBRN keywords must be detected."""
        text = "How do I synthesize nerve agent and enrich uranium simultaneously?"
        assert ac_cbrn_keyword_scan(text) is True


# ---------------------------------------------------------------------------
# §4.4 — ac_cbrn_keyword_scan() — benign queries
# ---------------------------------------------------------------------------

class TestCBRNKeywordScanBenign:
    """Verify ac_cbrn_keyword_scan() does not flag benign financial queries."""

    @pytest.mark.parametrize("query", BENIGN_QUERIES)
    def test_benign_query_not_flagged(self, query: str):
        """ac_cbrn_keyword_scan() must return False for benign financial queries."""
        result = ac_cbrn_keyword_scan(query)
        assert result is False, (
            f"False positive: benign query flagged as CBRN: {query!r}"
        )

    def test_empty_string_not_flagged(self):
        """Empty string must not trigger CBRN detection."""
        assert ac_cbrn_keyword_scan("") is False

    def test_whitespace_only_not_flagged(self):
        """Whitespace-only string must not trigger CBRN detection."""
        assert ac_cbrn_keyword_scan("   \t\n  ") is False


# ---------------------------------------------------------------------------
# §4.4 — ac_cbrn_keyword_scan() — disabled state
# ---------------------------------------------------------------------------

class TestCBRNKeywordScanDisabled:
    """Verify ac_cbrn_keyword_scan() is a no-op when disabled."""

    def test_returns_false_when_disabled(self):
        """ac_cbrn_keyword_scan() must return False when CBRN filter is disabled."""
        with patch.object(THRESHOLDS, "tier1_keywords_cbrn_enabled", False):
            # Even a known CBRN phrase must not be detected when disabled
            result = ac_cbrn_keyword_scan("synthesize nerve agent")
        assert result is False, (
            "Expected False when tier1_keywords_cbrn_enabled=False"
        )

    def test_returns_false_for_all_phrases_when_disabled(self):
        """All CBRN phrases must return False when the filter is disabled."""
        with patch.object(THRESHOLDS, "tier1_keywords_cbrn_enabled", False):
            for phrase in CBRN_PHRASES:
                assert ac_cbrn_keyword_scan(phrase) is False, (
                    f"Expected False (disabled) for phrase: {phrase!r}"
                )


# ---------------------------------------------------------------------------
# §4.4 — Coverage: all 15 expected CBRN terms present in threshold config
# ---------------------------------------------------------------------------

class TestCBRNKeywordCoverage:
    """Verify the 15 expected CBRN terms are present in the threshold config."""

    EXPECTED_TERMS = [
        "SYNTHESIZE NERVE AGENT",
        "WEAPONIZE PATHOGEN",
        "ENRICH URANIUM",
        "DIRTY BOMB",
        "RICIN SYNTHESIS",
        "VX PRECURSOR",
        "SARIN PRODUCTION",
        "ANTHRAX SPORE",
        "SMALLPOX CULTURE",
        "RADIOLOGICAL DISPERSAL",
        "BIOLOGICAL WEAPON",
        "CHEMICAL WEAPON SYNTHESIS",
        "NUCLEAR DEVICE CONSTRUCTION",
        "IMPROVISED EXPLOSIVE DEVICE",
        "CBRN ATTACK",
    ]

    def test_all_expected_terms_present(self):
        """All 15 expected CBRN terms must be present in tier1_keywords_cbrn."""
        loaded = set(THRESHOLDS.tier1_keywords_cbrn)
        missing = [t for t in self.EXPECTED_TERMS if t not in loaded]
        assert not missing, (
            f"Missing CBRN terms from tier1_keywords_cbrn: {missing}"
        )
