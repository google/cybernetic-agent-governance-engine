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
test_provider_03.py — Provider 03 Adapter Tests
===============================================

Tests for the Provider 03 NormativeProvider adapter including:
- Protocol compliance (correct method signatures and return types)
- HTTP error handling (HTTPStatusError, RequestError)
- ESCALATE verdict mapping to CAGE's REVIEW/DEFER semantic
- Fail-closed behavior
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.integrations.provider_03.provider import (
    FINDING_CODE_ENDPOINT_ERROR,
    Provider03NormativeProvider,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def adapter() -> Provider03NormativeProvider:
    """Create an adapter with a mock endpoint."""
    return Provider03NormativeProvider(
        endpoint="http://localhost:8080",
        api_key="test-api-key",
        timeout=5.0,
    )


@pytest.fixture
def adapter_no_endpoint() -> Provider03NormativeProvider:
    """Create an adapter without an endpoint configured."""
    return Provider03NormativeProvider(
        endpoint="",
        api_key="",
        timeout=5.0,
    )


def _mock_response(json_data: dict[str, Any], status_code: int = 200) -> MagicMock:
    """Create a mock httpx response."""
    mock = MagicMock()
    mock.json.return_value = json_data
    mock.raise_for_status = MagicMock()
    mock.headers = {"ETag": "test-etag-123"}
    mock.status_code = status_code
    return mock


# ---------------------------------------------------------------------------
# Protocol Compliance Tests
# ---------------------------------------------------------------------------


class TestProtocolCompliance:
    """Tests for NormativeProvider protocol compliance."""

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_fetch_baseline_returns_normative_baseline(
        self,
        adapter: Provider03NormativeProvider,
    ) -> None:
        """fetch_baseline returns NormativeBaseline dataclass."""
        mock_response = _mock_response(
            {
                "profile": {"rules": ["DECISION_MANDATE_V1"]},
            }
        )

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.fetch_baseline("US_FED")

        from src.gateway.governance.normative_provider import NormativeBaseline

        assert isinstance(result, NormativeBaseline)
        assert result.region == "US_FED"
        assert result.profile == {"rules": ["DECISION_MANDATE_V1"]}
        assert result.etag == "test-etag-123"
        assert result.error is None

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_validate_fria_approved_returns_admitted_true(
        self,
        adapter: Provider03NormativeProvider,
    ) -> None:
        """APPROVED verdict maps to admitted=True."""
        mock_response = _mock_response(
            {
                "verdict": "APPROVED",
                "findings": [],
            }
        )

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        from src.gateway.governance.normative_provider import ValidationResult

        assert isinstance(result, ValidationResult)
        assert result.admitted is True
        assert result.findings == []
        assert result.error is None

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_validate_fria_rejected_returns_admitted_false(
        self,
        adapter: Provider03NormativeProvider,
    ) -> None:
        """REJECTED verdict maps to admitted=False."""
        mock_response = _mock_response(
            {
                "verdict": "REJECTED",
                "findings": [
                    {"code": "policy.violation", "message": "Policy violated"}
                ],
            }
        )

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "policy.violation"

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_submit_evidence_returns_evidence_seal(
        self,
        adapter: Provider03NormativeProvider,
    ) -> None:
        """submit_evidence returns EvidenceSeal dataclass."""
        mock_response = _mock_response(
            {
                "seal_hash": "sha256-def456",
            }
        )

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.submit_evidence("thread-456", "evidence-hash")

        from src.gateway.governance.normative_provider import EvidenceSeal

        assert isinstance(result, EvidenceSeal)
        assert result.thread_id == "thread-456"
        assert result.seal_hash == "sha256-def456"
        assert result.error is None


# ---------------------------------------------------------------------------
# ESCALATE Verdict Mapping Tests
# ---------------------------------------------------------------------------


class TestEscalateVerdictMapping:
    """Tests for ESCALATE verdict mapping to CAGE's REVIEW/DEFER semantic."""

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_escalate_verdict_maps_to_admitted_false_with_review_marker(
        self,
        adapter: Provider03NormativeProvider,
    ) -> None:
        """ESCALATE verdict maps to admitted=False + needs_human_review marker."""
        mock_response = _mock_response(
            {
                "verdict": "ESCALATE",
                "findings": [{"code": "confidence.low", "message": "Low confidence"}],
            }
        )

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        assert result.admitted is False
        # First finding should have needs_human_review marker
        review_findings = [f for f in result.findings if f.get("needs_human_review")]
        assert len(review_findings) == 1
        assert review_findings[0]["code"] == "provider_03.escalate"
        assert review_findings[0]["needs_human_review"] is True
        assert review_findings[0]["provider_03_verdict"] == "ESCALATE"

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_escalate_preserves_original_findings(
        self,
        adapter: Provider03NormativeProvider,
    ) -> None:
        """ESCALATE verdict preserves original Provider 03 findings."""
        mock_response = _mock_response(
            {
                "verdict": "ESCALATE",
                "findings": [
                    {"code": "confidence.low", "message": "Low confidence"},
                    {"code": "authority.unclear", "message": "Authority unclear"},
                ],
            }
        )

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        # Original findings should be appended after the escalate marker
        finding_codes = [f["code"] for f in result.findings]
        assert "provider_03.escalate" in finding_codes
        assert "confidence.low" in finding_codes
        assert "authority.unclear" in finding_codes


# ---------------------------------------------------------------------------
# Error Handling Tests
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Tests for HTTP error handling and fail-closed behavior."""

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_no_endpoint_returns_error_on_validate_fria(
        self,
        adapter_no_endpoint: Provider03NormativeProvider,
    ) -> None:
        """Missing endpoint returns admitted=False with ENDPOINT_ERROR."""
        result = await adapter_no_endpoint.validate_fria({"action": "test"})

        assert result.admitted is False
        assert "not configured" in (result.error or "").lower()
        assert any(f["code"] == FINDING_CODE_ENDPOINT_ERROR for f in result.findings)

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_no_endpoint_returns_error_on_fetch_baseline(
        self,
        adapter_no_endpoint: Provider03NormativeProvider,
    ) -> None:
        """Missing endpoint returns NormativeBaseline with error."""
        result = await adapter_no_endpoint.fetch_baseline("US_FED")

        assert result.region == "US_FED"
        assert result.profile == {}
        assert "not configured" in (result.error or "").lower()

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_no_endpoint_returns_error_on_submit_evidence(
        self,
        adapter_no_endpoint: Provider03NormativeProvider,
    ) -> None:
        """Missing endpoint returns EvidenceSeal with error."""
        result = await adapter_no_endpoint.submit_evidence("thread-123", "hash")

        assert result.thread_id == "thread-123"
        assert "not configured" in (result.error or "").lower()

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_http_status_error_on_validate_fria_returns_rich_findings(
        self,
        adapter: Provider03NormativeProvider,
    ) -> None:
        """HTTPStatusError returns admitted=False with ENDPOINT_ERROR finding."""
        import httpx

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_response.text = "Internal Server Error"
            client_instance.post.side_effect = httpx.HTTPStatusError(
                message="Server Error",
                request=MagicMock(),
                response=mock_response,
            )
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        assert result.admitted is False
        assert result.error == "HTTP 500"
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == FINDING_CODE_ENDPOINT_ERROR
        assert "500" in result.findings[0]["message"]

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_request_error_on_validate_fria_returns_rich_findings(
        self,
        adapter: Provider03NormativeProvider,
    ) -> None:
        """RequestError returns admitted=False with ENDPOINT_ERROR finding."""
        import httpx

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.side_effect = httpx.ConnectError("Connection refused")
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == FINDING_CODE_ENDPOINT_ERROR


# ---------------------------------------------------------------------------
# Bind Receipt Tests
# ---------------------------------------------------------------------------


class TestBindReceipt:
    """Tests for Provider 03-specific bind receipt ingestion."""

    def test_ingest_bind_receipt_returns_canonical_hash(
        self,
        adapter: Provider03NormativeProvider,
    ) -> None:
        """ingest_bind_receipt returns deterministic SHA-256 hash."""
        receipt = {
            "receipt_id": "test-receipt-123",
            "authority": "provider_03",
            "decision": "APPROVED",
        }

        hash1 = adapter.ingest_bind_receipt(receipt)
        hash2 = adapter.ingest_bind_receipt(receipt)

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex digest


# ---------------------------------------------------------------------------
# Factory Registration Tests
# ---------------------------------------------------------------------------


class TestFactoryRegistration:
    """Tests for provider_03 registration in the factory."""

    def test_provider_03_is_registered(self) -> None:
        """provider_03 is listed in available providers."""
        from src.gateway.governance.normative_provider import get_normative_provider

        # Attempting to get an unknown provider should list provider_03
        try:
            get_normative_provider("nonexistent_provider")
        except ValueError as exc:
            assert "provider_03" in str(exc)

    @pytest.mark.local
    def test_provider_03_instantiates(self) -> None:
        """provider_03 can be instantiated via factory."""
        from src.gateway.governance.normative_provider import get_normative_provider

        provider = get_normative_provider("provider_03")
        assert isinstance(provider, Provider03NormativeProvider)
