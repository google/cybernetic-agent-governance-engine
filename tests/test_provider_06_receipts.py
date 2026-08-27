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
test_provider_06_receipts.py — Agent Integrity Adapter Tests
============================================================

Tests the provider_06 adapter against conformance fixtures from the
Agent Integrity repository.

Conformance fixtures:
  - pass.json    → PASS verdict (admitted=True)
  - review.json  → REVIEW verdict (admitted=False + needs_human_review)
  - blocked.json → BLOCKED verdict (admitted=False)

These tests verify that the CAGE adapter correctly:
1. Parses Agent Integrity's tri-state verdicts
2. Maps verdicts to ValidationResult.admitted boolean
3. Preserves findings and markers for defer-queue handling
4. Handles error cases gracefully (fail-closed)
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

VALID_ENVELOPE = {
    "protocolVersion": "1-alpha",
    "policy": {
        "version": 1,
        "sources": {"allowedRoots": ["docs/"]},
        "decisions": {"path": "integrity/decisions.yaml"},
        "rules": {
            "requireEvidenceFor": ["factual"],
            "contradictions": "review",
            "rejectedDecisions": "block",
            "responseMutation": "block",
            "replay": "block",
        },
    },
    "response": {"content": "", "sections": []},
    "sources": [],
    "decisionRegistryDigest": "0000000000000000000000000000000000000000000000000000000000000000",
    "decisions": [],
    "evidence": [],
    "claims": [],
}


import pytest

from src.integrations.provider_06.adapter import (
    FINDING_CODE_ENDPOINT_ERROR,
    FINDING_CODE_PARSE_ERROR,
    FINDING_CODE_REVIEW_PENDING,
    PROTOCOL_VERSION,
    FindingSeverity,
    IntegrityFinding,
    IntegrityResult,
    IntegrityStatus,
    Provider06AgentIntegrityAdapter,
    extract_integrity_status,
    is_review_pending,
)
from src.integrations.provider_06.mock_endpoint import FIXTURES

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def adapter() -> Provider06AgentIntegrityAdapter:
    """Create an adapter with a mock endpoint."""
    return Provider06AgentIntegrityAdapter(
        endpoint="http://localhost:8090",
        project_root="/test/project",
        timeout=5.0,
    )


@pytest.fixture
def adapter_no_endpoint() -> Provider06AgentIntegrityAdapter:
    """Create an adapter without an endpoint configured."""
    return Provider06AgentIntegrityAdapter(
        endpoint="",
        project_root="",
        timeout=5.0,
    )


# ---------------------------------------------------------------------------
# Protocol Type Tests
# ---------------------------------------------------------------------------


class TestIntegrityStatus:
    """Tests for IntegrityStatus enum."""

    def test_status_values(self) -> None:
        """Verify the three status values match Agent Integrity protocol."""
        assert IntegrityStatus.PASS.value == "PASS"
        assert IntegrityStatus.REVIEW.value == "REVIEW"
        assert IntegrityStatus.BLOCKED.value == "BLOCKED"

    def test_status_from_string(self) -> None:
        """Status can be constructed from string value."""
        assert IntegrityStatus("PASS") == IntegrityStatus.PASS
        assert IntegrityStatus("REVIEW") == IntegrityStatus.REVIEW
        assert IntegrityStatus("BLOCKED") == IntegrityStatus.BLOCKED


class TestIntegrityFinding:
    """Tests for IntegrityFinding dataclass."""

    def test_finding_to_dict(self) -> None:
        """Finding serializes to JSON-compatible dict."""
        finding = IntegrityFinding(
            code="claim.support_ambiguous",
            severity=FindingSeverity.REVIEW,
            message="Evidence support is ambiguous",
            path="response.claims[0]",
        )
        result = finding.to_dict()
        assert result["code"] == "claim.support_ambiguous"
        assert result["severity"] == "review"
        assert result["message"] == "Evidence support is ambiguous"
        assert result["path"] == "response.claims[0]"

    def test_finding_without_path(self) -> None:
        """Finding without path omits the key."""
        finding = IntegrityFinding(
            code="decision.superseded",
            severity=FindingSeverity.BLOCKED,
            message="Decision was superseded",
        )
        result = finding.to_dict()
        assert "path" not in result


class TestIntegrityResult:
    """Tests for IntegrityResult dataclass."""

    def test_result_to_dict(self) -> None:
        """Result serializes to JSON-compatible dict."""
        result = IntegrityResult(
            protocol_version=PROTOCOL_VERSION,
            status=IntegrityStatus.PASS,
            findings=(),
        )
        data = result.to_dict()
        assert data["protocolVersion"] == PROTOCOL_VERSION
        assert data["status"] == "PASS"
        assert data["findings"] == []

    def test_result_from_dict_pass(self) -> None:
        """Result deserializes from pass fixture."""
        data = FIXTURES["pass"]
        result = IntegrityResult.from_dict(data)
        assert result.status == IntegrityStatus.PASS
        assert len(result.findings) == 0

    def test_result_from_dict_review(self) -> None:
        """Result deserializes from review fixture."""
        data = FIXTURES["review"]
        result = IntegrityResult.from_dict(data)
        assert result.status == IntegrityStatus.REVIEW
        assert len(result.findings) == 1
        assert result.findings[0].code == "claim.support_ambiguous"
        assert result.findings[0].severity == FindingSeverity.REVIEW

    def test_result_from_dict_blocked(self) -> None:
        """Result deserializes from blocked fixture."""
        data = FIXTURES["blocked"]
        result = IntegrityResult.from_dict(data)
        assert result.status == IntegrityStatus.BLOCKED
        assert len(result.findings) == 1
        assert result.findings[0].code == "decision.superseded"
        assert result.findings[0].severity == FindingSeverity.BLOCKED


# ---------------------------------------------------------------------------
# Adapter Tests — Tri-State Verdict Mapping
# ---------------------------------------------------------------------------


def _mock_response(json_data: dict[str, Any]) -> MagicMock:
    """Create a mock httpx response with synchronous json() method."""
    mock = MagicMock()
    mock.json.return_value = json_data
    mock.raise_for_status = MagicMock()
    return mock


class TestTriStateVerdictMapping:
    """Tests for tri-state verdict mapping in validate_fria()."""

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_pass_verdict_maps_to_admitted_true(
        self,
        adapter: Provider06AgentIntegrityAdapter,
    ) -> None:
        """PASS verdict → admitted=True."""
        mock_response = _mock_response(FIXTURES["pass"])

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(VALID_ENVELOPE)

        assert result.admitted is True
        assert result.error is None

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_blocked_verdict_maps_to_admitted_false(
        self,
        adapter: Provider06AgentIntegrityAdapter,
    ) -> None:
        """BLOCKED verdict → admitted=False with blocked findings."""
        mock_response = _mock_response(FIXTURES["blocked"])

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(VALID_ENVELOPE)

        assert result.admitted is False
        assert result.error is None
        # Should contain the blocked finding
        assert any(f["code"] == "decision.superseded" for f in result.findings)

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_review_verdict_maps_to_admitted_false_with_marker(
        self,
        adapter: Provider06AgentIntegrityAdapter,
    ) -> None:
        """REVIEW verdict → admitted=False + needs_human_review marker."""
        mock_response = _mock_response(FIXTURES["review"])

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(VALID_ENVELOPE)

        assert result.admitted is False
        assert result.error is None

        # Should contain the review pending marker
        review_findings = [
            f for f in result.findings if f.get("needs_human_review", False)
        ]
        assert len(review_findings) == 1
        assert review_findings[0]["code"] == FINDING_CODE_REVIEW_PENDING
        assert review_findings[0]["integrity_status"] == "REVIEW"

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_review_preserves_original_findings(
        self,
        adapter: Provider06AgentIntegrityAdapter,
    ) -> None:
        """REVIEW verdict preserves the original Agent Integrity findings."""
        mock_response = _mock_response(FIXTURES["review"])

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(VALID_ENVELOPE)

        # Original findings should be appended after the review marker
        original_finding_codes = [
            f["code"]
            for f in result.findings
            if f["code"] != FINDING_CODE_REVIEW_PENDING
        ]
        assert "claim.support_ambiguous" in original_finding_codes


# ---------------------------------------------------------------------------
# Adapter Tests — Error Handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Tests for error handling in the adapter."""

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_no_endpoint_returns_error(
        self,
        adapter_no_endpoint: Provider06AgentIntegrityAdapter,
    ) -> None:
        """Missing endpoint → admitted=False + endpoint error."""
        result = await adapter_no_endpoint.validate_fria(VALID_ENVELOPE)

        assert result.admitted is False
        assert "not configured" in (result.error or "").lower()
        assert any(f["code"] == FINDING_CODE_ENDPOINT_ERROR for f in result.findings)

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_http_error_fails_closed(
        self,
        adapter: Provider06AgentIntegrityAdapter,
    ) -> None:
        """HTTP error → admitted=False (fail-closed)."""
        import httpx

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status_code = 500
            mock_response.text = "Internal Server Error"
            client_instance.post.side_effect = httpx.HTTPStatusError(
                message="Server Error",
                request=AsyncMock(),
                response=mock_response,
            )
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(VALID_ENVELOPE)

        assert result.admitted is False
        assert any(f["code"] == FINDING_CODE_ENDPOINT_ERROR for f in result.findings)

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_connection_error_fails_closed(
        self,
        adapter: Provider06AgentIntegrityAdapter,
    ) -> None:
        """Connection error → admitted=False (fail-closed)."""
        import httpx

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.side_effect = httpx.ConnectError("Connection refused")
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(VALID_ENVELOPE)

        assert result.admitted is False
        assert any(f["code"] == FINDING_CODE_ENDPOINT_ERROR for f in result.findings)

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_parse_error_fails_closed(
        self,
        adapter: Provider06AgentIntegrityAdapter,
    ) -> None:
        """Invalid JSON response → admitted=False (fail-closed)."""
        mock_response = MagicMock()
        mock_response.json.side_effect = json.JSONDecodeError(
            "Invalid JSON", doc="", pos=0
        )
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(VALID_ENVELOPE)

        assert result.admitted is False
        assert any(f["code"] == FINDING_CODE_PARSE_ERROR for f in result.findings)


# ---------------------------------------------------------------------------
# Helper Function Tests
# ---------------------------------------------------------------------------


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_is_review_pending_true(self) -> None:
        """is_review_pending returns True when marker present."""
        findings = [
            {"code": FINDING_CODE_REVIEW_PENDING, "needs_human_review": True},
            {"code": "claim.support_ambiguous"},
        ]
        assert is_review_pending(findings) is True

    def test_is_review_pending_false(self) -> None:
        """is_review_pending returns False when no marker."""
        findings = [
            {"code": "decision.superseded", "severity": "blocked"},
        ]
        assert is_review_pending(findings) is False

    def test_is_review_pending_empty(self) -> None:
        """is_review_pending returns False for empty list."""
        assert is_review_pending([]) is False

    def test_extract_integrity_status_found(self) -> None:
        """extract_integrity_status returns status when present."""
        findings = [
            {"code": FINDING_CODE_REVIEW_PENDING, "integrity_status": "REVIEW"},
        ]
        assert extract_integrity_status(findings) == "REVIEW"

    def test_extract_integrity_status_not_found(self) -> None:
        """extract_integrity_status returns None when not present."""
        findings = [
            {"code": "decision.superseded"},
        ]
        assert extract_integrity_status(findings) is None


# ---------------------------------------------------------------------------
# Fetch Baseline Tests
# ---------------------------------------------------------------------------


class TestFetchBaseline:
    """Tests for fetch_baseline() method."""

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_fetch_baseline_returns_verifier_info(
        self,
        adapter: Provider06AgentIntegrityAdapter,
    ) -> None:
        """fetch_baseline returns minimal baseline with verifier info."""
        result = await adapter.fetch_baseline("US_FED")

        assert result.region == "US_FED"
        assert result.error is None
        assert result.profile["verifier"] == "agent-integrity"
        assert result.profile["protocol_version"] == PROTOCOL_VERSION


# ---------------------------------------------------------------------------
# Submit Evidence Tests
# ---------------------------------------------------------------------------


class TestSubmitEvidence:
    """Tests for submit_evidence() method."""

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_submit_evidence_no_endpoint(
        self,
        adapter_no_endpoint: Provider06AgentIntegrityAdapter,
    ) -> None:
        """submit_evidence with no endpoint returns error."""
        result = await adapter_no_endpoint.submit_evidence(
            thread_id="test-123",
            evidence_hash="abc123",
        )

        assert result.thread_id == "test-123"
        assert result.error is not None
        assert "not configured" in result.error.lower()

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_submit_evidence_success(
        self,
        adapter: Provider06AgentIntegrityAdapter,
    ) -> None:
        """submit_evidence returns seal hash on success."""
        mock_response = _mock_response({"receiptDigest": "sha256-abc123def456"})

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.submit_evidence(
                thread_id="test-123",
                evidence_hash="evidence-hash-456",
            )

        assert result.thread_id == "test-123"
        assert result.seal_hash == "sha256-abc123def456"
        assert result.error is None


# ---------------------------------------------------------------------------
# Provider Factory Registration Tests
# ---------------------------------------------------------------------------


class TestProviderFactoryRegistration:
    """Tests for provider_06 registration in the factory."""

    def test_provider_06_is_registered(self) -> None:
        """provider_06 is listed in available providers."""
        from src.gateway.governance.normative_provider import get_normative_provider

        # Attempting to get an unknown provider should list provider_06
        try:
            get_normative_provider("nonexistent_provider")
        except ValueError as exc:
            assert "provider_06" in str(exc)

    @pytest.mark.local
    def test_provider_06_instantiates(self) -> None:
        """provider_06 can be instantiated via factory."""
        from src.gateway.governance.normative_provider import get_normative_provider

        provider = get_normative_provider("provider_06")
        assert isinstance(provider, Provider06AgentIntegrityAdapter)


# ---------------------------------------------------------------------------
# Conformance Fixture Integration Tests
# ---------------------------------------------------------------------------


class TestConformanceFixtures:
    """Tests using Agent Integrity conformance fixtures."""

    @pytest.mark.parametrize(
        "fixture_name,expected_status",
        [
            ("pass", IntegrityStatus.PASS),
            ("review", IntegrityStatus.REVIEW),
            ("blocked", IntegrityStatus.BLOCKED),
            ("checker_failure", IntegrityStatus.BLOCKED),
            ("contradictory_evidence", IntegrityStatus.REVIEW),
            ("missing_evidence", IntegrityStatus.BLOCKED),
        ],
    )
    def test_all_fixtures_parse_correctly(
        self,
        fixture_name: str,
        expected_status: IntegrityStatus,
    ) -> None:
        """All mock fixtures parse to expected status."""
        data = FIXTURES[fixture_name]
        result = IntegrityResult.from_dict(data)
        assert result.status == expected_status

    @pytest.mark.parametrize(
        "fixture_name,expected_admitted",
        [
            ("pass", True),
            ("review", False),
            ("blocked", False),
            ("checker_failure", False),
            ("contradictory_evidence", False),
            ("missing_evidence", False),
        ],
    )
    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_all_fixtures_map_to_correct_admitted(
        self,
        adapter: Provider06AgentIntegrityAdapter,
        fixture_name: str,
        expected_admitted: bool,
    ) -> None:
        """All fixtures map to correct admitted value."""
        mock_response = _mock_response(FIXTURES[fixture_name])

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(VALID_ENVELOPE)

        assert result.admitted is expected_admitted
