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
Conformance tests for canonical governance decision models (DEFER, NARROW, PAUSE).
"""

from __future__ import annotations

import json

import pytest

from src.gateway.governance.decisions import (
    DeferResponse,
    GovernanceDecision,
    NarrowResponse,
    PauseResponse,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


class TestDeferResponseModel:
    """Tests for the DeferResponse Pydantic model."""

    def test_defer_response_default_values(self):
        """DeferResponse has correct default values."""
        resp = DeferResponse()

        assert resp.decision == "DEFER"
        assert resp.deferrable is True
        assert resp.retry_after_seconds == 300
        assert resp.defer_reason == "CONFIDENCE_BELOW_THRESHOLD"
        assert resp.violations == []
        assert resp.defer_token == ""

    def test_defer_response_to_http_body(self):
        """DeferResponse.to_http_body() produces correct structure."""
        resp = DeferResponse(
            classification_reason="Low confidence",
            defer_token="test-token-abc",
            violations=["Confidence below threshold"],
        )

        body = resp.to_http_body()

        assert body["decision"] == "DEFER"
        assert body["classification_reason"] == "Low confidence"
        assert body["defer_token"] == "test-token-abc"
        assert body["deferrable"] is True
        assert body["violations"] == ["Confidence below threshold"]
        assert "verdict" not in body
        assert "defer_id" not in body
        assert "missing_input_reason" not in body

    def test_defer_response_serialization(self):
        """DeferResponse can be serialized to JSON."""
        resp = DeferResponse(
            defer_token="serialize-test",
            classification_reason="Test serialization",
        )

        json_str = resp.model_dump_json()
        parsed = json.loads(json_str)

        assert parsed["defer_token"] == "serialize-test"
        assert parsed["classification_reason"] == "Test serialization"


class TestNarrowResponseModel:
    """Tests for the NarrowResponse Pydantic model."""

    def test_narrow_response_default_values(self):
        """NarrowResponse has correct default values."""
        resp = NarrowResponse()

        assert resp.decision == "NARROW"
        assert resp.execution_allowed is True
        assert resp.original_params == {}
        assert resp.narrowed_params == {}
        assert resp.constraints_applied == []
        assert resp.narrowing_reason == ""

    def test_narrow_response_to_http_body(self):
        """NarrowResponse.to_http_body() produces correct structure."""
        resp = NarrowResponse(
            original_params={"amount": 150000},
            narrowed_params={"amount": 100000},
            narrowing_reason="Amount clamped to max_allowed",
            constraints_applied=["amount clamped: 150000 → 100000"],
        )

        body = resp.to_http_body()

        assert body["decision"] == "NARROW"
        assert body["original_params"]["amount"] == 150000
        assert body["narrowed_params"]["amount"] == 100000
        assert body["execution_allowed"] is True
        assert body["verdict"] == GovernanceDecision.NARROW
        assert len(body["constraints_applied"]) == 1


class TestPauseResponseModel:
    """Tests for the PauseResponse Pydantic model."""

    def test_pause_response_required_fields(self):
        """PauseResponse requires pause_token, pause_reason, etc."""
        from datetime import datetime, timezone

        resp = PauseResponse(
            pause_token="test-pause-token",
            pause_reason="RATE_LIMITED",
            resume_endpoint="/v1/pause/test-pause-token/resume",
            expires_at=datetime.now(tz=timezone.utc),
        )

        assert resp.decision == "PAUSE"
        assert resp.pause_token == "test-pause-token"
        assert resp.pause_reason == "RATE_LIMITED"
        assert "/resume" in resp.resume_endpoint

    def test_pause_response_to_http_body(self):
        """PauseResponse.to_http_body() produces correct structure."""
        from datetime import datetime, timezone

        expires = datetime(2026, 8, 15, 14, 0, 0, tzinfo=timezone.utc)

        resp = PauseResponse(
            pause_token="pause-http-test",
            pause_reason="CIRCUIT_OPEN",
            resume_endpoint="/v1/pause/pause-http-test/resume",
            expires_at=expires,
            estimated_wait_seconds=60,
            retry_after_seconds=30,
        )

        body = resp.to_http_body()

        assert body["decision"] == "PAUSE"
        assert body["pause_token"] == "pause-http-test"
        assert body["pause_reason"] == "CIRCUIT_OPEN"
        assert body["resume_endpoint"] == "/v1/pause/pause-http-test/resume"
        assert body["expires_at"] == "2026-08-15T14:00:00+00:00"
        assert body["estimated_wait_seconds"] == 60
        assert body["retry_after_seconds"] == 30
        assert body["verdict"] == GovernanceDecision.PAUSE


class TestDecisionVocabularyConformance:
    """Conformance tests for GovernanceDecision canonical vocabulary."""

    def test_all_governance_decisions_are_defined(self):
        """All five canonical decisions are defined in GovernanceDecision."""
        assert hasattr(GovernanceDecision, "ALLOW")
        assert hasattr(GovernanceDecision, "DENY")
        assert hasattr(GovernanceDecision, "DEFER")
        assert hasattr(GovernanceDecision, "NARROW")
        assert hasattr(GovernanceDecision, "PAUSE")
        assert hasattr(GovernanceDecision, "REQUIRE_APPROVAL")

    def test_governance_decision_values(self):
        """GovernanceDecision enum values match expected strings."""
        assert GovernanceDecision.ALLOW.value == "ALLOW"
        assert GovernanceDecision.DENY.value == "DENY"
        assert GovernanceDecision.DEFER.value == "DEFER"
        assert GovernanceDecision.NARROW.value == "NARROW"
        assert GovernanceDecision.PAUSE.value == "PAUSE"
        assert GovernanceDecision.REQUIRE_APPROVAL.value == "REQUIRE_APPROVAL"

    def test_governance_decision_is_string_enum(self):
        """GovernanceDecision inherits from str for JSON serialization."""
        assert isinstance(GovernanceDecision.ALLOW, str)
        assert GovernanceDecision.DEFER == "DEFER"
