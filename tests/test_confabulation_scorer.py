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

"""Tests for confabulation scorer — AI 600-1 §2.1 (CTRL_AGT_001).

POAM: AI600-001
Phase: 1 (quick wins)
"""

import pytest

from src.gateway.governance.confabulation_scorer import (
    ConfabulationEvent,
    CONFIDENCE_THRESHOLD,
    is_confabulation_blocked,
    score_confabulation,
)


class TestScoreConfabulation:
    """score_confabulation must return correct Langfuse score payload."""

    def test_score_value_is_one_minus_confidence(self):
        """score_confabulation returns value = 1.0 - confidence."""
        event = ConfabulationEvent(
            trace_id="trace-001",
            confidence=0.87,
            model_id="deepseek-r1",
            grounding_source=None,
            blocked=True,
        )
        payload = score_confabulation(event)
        assert abs(payload["value"] - (1.0 - 0.87)) < 1e-9

    def test_score_name_is_confabulation_risk(self):
        """score_confabulation returns name='confabulation_risk'."""
        event = ConfabulationEvent(
            trace_id="trace-002",
            confidence=0.95,
            model_id="llama-3.1",
            grounding_source="market_data_api",
            blocked=False,
        )
        payload = score_confabulation(event)
        assert payload["name"] == "confabulation_risk"

    def test_trace_id_in_payload(self):
        """score_confabulation includes trace_id in the payload."""
        event = ConfabulationEvent(
            trace_id="trace-xyz-123",
            confidence=0.90,
            model_id="deepseek-r1",
            grounding_source=None,
            blocked=False,
        )
        payload = score_confabulation(event)
        assert payload["trace_id"] == "trace-xyz-123"

    def test_payload_schema_has_required_fields(self):
        """score_confabulation payload has all required Langfuse score fields."""
        event = ConfabulationEvent(
            trace_id="trace-003",
            confidence=0.80,
            model_id="deepseek-r1",
            grounding_source="earnings_api",
            blocked=True,
        )
        payload = score_confabulation(event)
        required_fields = {"name", "value", "comment", "trace_id", "data_type"}
        assert required_fields.issubset(payload.keys())

    def test_data_type_is_numeric(self):
        """score_confabulation returns data_type='NUMERIC'."""
        event = ConfabulationEvent(
            trace_id="trace-004",
            confidence=0.99,
            model_id="llama-3.1",
            grounding_source=None,
            blocked=False,
        )
        payload = score_confabulation(event)
        assert payload["data_type"] == "NUMERIC"

    def test_high_confidence_yields_low_risk(self):
        """High confidence (0.99) yields low confabulation risk (0.01)."""
        event = ConfabulationEvent(
            trace_id="trace-005",
            confidence=0.99,
            model_id="deepseek-r1",
            grounding_source=None,
            blocked=False,
        )
        payload = score_confabulation(event)
        assert payload["value"] < 0.05

    def test_low_confidence_yields_high_risk(self):
        """Low confidence (0.50) yields high confabulation risk (0.50)."""
        event = ConfabulationEvent(
            trace_id="trace-006",
            confidence=0.50,
            model_id="deepseek-r1",
            grounding_source=None,
            blocked=True,
        )
        payload = score_confabulation(event)
        assert abs(payload["value"] - 0.50) < 1e-9

    def test_comment_includes_confidence_and_threshold(self):
        """score_confabulation comment includes confidence and threshold values."""
        event = ConfabulationEvent(
            trace_id="trace-007",
            confidence=0.87,
            model_id="deepseek-r1",
            grounding_source=None,
            blocked=True,
        )
        payload = score_confabulation(event)
        assert "confidence=0.870" in payload["comment"]
        assert "threshold=" in payload["comment"]


class TestIsConfabulationBlocked:
    """is_confabulation_blocked must correctly apply the threshold."""

    def test_blocked_below_threshold(self):
        """Confidence below threshold triggers a block."""
        assert is_confabulation_blocked(0.94) is True

    def test_not_blocked_at_threshold(self):
        """Confidence exactly at threshold does not trigger a block."""
        assert is_confabulation_blocked(CONFIDENCE_THRESHOLD) is False

    def test_not_blocked_above_threshold(self):
        """Confidence above threshold does not trigger a block."""
        assert is_confabulation_blocked(0.99) is False

    def test_zero_confidence_is_blocked(self):
        """Zero confidence is always blocked."""
        assert is_confabulation_blocked(0.0) is True

    def test_perfect_confidence_is_not_blocked(self):
        """Perfect confidence (1.0) is never blocked."""
        assert is_confabulation_blocked(1.0) is False
