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
test_provider_01.py — Provider 01 Adapter Tests
===============================================

Tests for the Provider 01 NormativeProvider adapter including:
- Protocol compliance (correct method signatures and return types)
- HTTP error handling (HTTPStatusError, RequestError)
- Rich findings generation on failure
- Fail-closed behavior
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.integrations.provider_01.provider import Provider01NormativeProvider

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def adapter() -> Provider01NormativeProvider:
    """Create an adapter with a mock endpoint."""
    return Provider01NormativeProvider(
        endpoint="http://localhost:8080",
        api_key="test-api-key",
        timeout=5.0,
    )


@pytest.fixture
def adapter_no_endpoint() -> Provider01NormativeProvider:
    """Create an adapter without an endpoint configured."""
    return Provider01NormativeProvider(
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
        adapter: Provider01NormativeProvider,
    ) -> None:
        """fetch_baseline returns NormativeBaseline dataclass."""
        mock_response = _mock_response(
            {
                "profile": {"controls": ["AC-1", "AC-2"]},
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
        assert result.profile == {"controls": ["AC-1", "AC-2"]}
        assert result.etag == "test-etag-123"
        assert result.error is None

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_validate_fria_returns_validation_result(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """validate_fria returns ValidationResult dataclass."""
        mock_response = _mock_response(
            {
                "admitted": True,
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
    async def test_submit_evidence_returns_evidence_seal(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """submit_evidence returns EvidenceSeal dataclass."""
        mock_response = _mock_response(
            {
                "seal_hash": "sha256-abc123",
            }
        )

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.submit_evidence("thread-123", "evidence-hash")

        from src.gateway.governance.normative_provider import EvidenceSeal

        assert isinstance(result, EvidenceSeal)
        assert result.thread_id == "thread-123"
        assert result.seal_hash == "sha256-abc123"
        assert result.error is None


# ---------------------------------------------------------------------------
# Error Handling Tests
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Tests for HTTP error handling and fail-closed behavior."""

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_http_status_error_on_validate_fria_returns_rich_findings(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """HTTPStatusError returns admitted=False with ENDPOINT_ERROR finding."""
        import httpx

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 503
            mock_response.text = "Service Unavailable"
            client_instance.post.side_effect = httpx.HTTPStatusError(
                message="Service Error",
                request=MagicMock(),
                response=mock_response,
            )
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        assert result.admitted is False
        assert result.error == "HTTP 503"
        # Verify rich findings are present
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "ENDPOINT_ERROR"
        assert result.findings[0]["severity"] == "blocked"
        assert "503" in result.findings[0]["message"]

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_request_error_on_validate_fria_returns_rich_findings(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """RequestError returns admitted=False with ENDPOINT_ERROR finding."""
        import httpx

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.side_effect = httpx.ConnectError("Connection refused")
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        assert result.admitted is False
        assert "Connection refused" in (result.error or "")
        # Verify rich findings are present
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "ENDPOINT_ERROR"
        assert result.findings[0]["severity"] == "blocked"

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_http_status_error_on_fetch_baseline_returns_error(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """HTTPStatusError on fetch_baseline returns NormativeBaseline with error."""
        import httpx

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_response.text = "Not Found"
            client_instance.get.side_effect = httpx.HTTPStatusError(
                message="Not Found",
                request=MagicMock(),
                response=mock_response,
            )
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.fetch_baseline("UNKNOWN_REGION")

        assert result.region == "UNKNOWN_REGION"
        assert result.profile == {}
        assert "HTTP 404" in (result.error or "")

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_request_error_on_submit_evidence_returns_error(
        self,
        adapter: Provider01NormativeProvider,
    ) -> None:
        """RequestError on submit_evidence returns EvidenceSeal with error."""
        import httpx

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get.side_effect = httpx.TimeoutException("Timeout")
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.submit_evidence("thread-123", "evidence-hash")

        assert result.thread_id == "thread-123"
        assert result.seal_hash == ""
        assert "Timeout" in (result.error or "")


# ---------------------------------------------------------------------------
# Factory Registration Tests
# ---------------------------------------------------------------------------


class TestFactoryRegistration:
    """Tests for provider_01 registration in the factory."""

    def test_provider_01_is_registered(self) -> None:
        """provider_01 is listed in available providers."""
        from src.gateway.governance.normative_provider import get_normative_provider

        # Attempting to get an unknown provider should list provider_01
        try:
            get_normative_provider("nonexistent_provider")
        except ValueError as exc:
            assert "provider_01" in str(exc)

    @pytest.mark.local
    def test_provider_01_instantiates(self) -> None:
        """provider_01 can be instantiated via factory."""
        from src.gateway.governance.normative_provider import get_normative_provider

        provider = get_normative_provider("provider_01")
        assert isinstance(provider, Provider01NormativeProvider)
