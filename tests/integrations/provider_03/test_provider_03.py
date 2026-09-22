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
    FINDING_CODE_PARSE_ERROR,
    Provider03NormativeProvider,
)

# Hermetic: tests Provider 03 adapter with mocks, no live services.
pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.partner]

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

        from src.gateway.governance.seams.normative import NormativeBaseline

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

        from src.gateway.governance.seams.normative import ValidationResult

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

        from src.gateway.governance.seams.normative import EvidenceSeal

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

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_json_decode_error_on_validate_fria_returns_parse_error_finding(
        self,
        adapter: Provider03NormativeProvider,
    ) -> None:
        """JSONDecodeError on validate_fria returns PARSE_ERROR finding."""
        import json

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_response.json.side_effect = json.JSONDecodeError(
                "Expecting value", "doc", 0
            )
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == FINDING_CODE_PARSE_ERROR
        assert result.findings[0]["severity"] == "blocked"
        assert "could not be decoded as JSON" in result.findings[0]["message"]

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_non_dict_response_on_validate_fria_returns_parse_error_finding(
        self,
        adapter: Provider03NormativeProvider,
    ) -> None:
        """Non-dict response on validate_fria returns PARSE_ERROR finding."""
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            # Test with list response
            mock_response.json.return_value = ["not", "a", "dict"]
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == FINDING_CODE_PARSE_ERROR
        assert result.findings[0]["severity"] == "blocked"
        assert "not a valid JSON object" in result.findings[0]["message"]

        # Test with string response
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_response.json.return_value = "OK"
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == FINDING_CODE_PARSE_ERROR
        assert result.findings[0]["severity"] == "blocked"

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_unexpected_exception_on_validate_fria_returns_endpoint_error(
        self,
        adapter: Provider03NormativeProvider,
    ) -> None:
        """Unexpected exception on validate_fria returns ENDPOINT_ERROR."""
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.side_effect = RuntimeError(
                "Unexpected connection drop"
            )
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == FINDING_CODE_ENDPOINT_ERROR
        assert result.findings[0]["severity"] == "blocked"
        assert "unexpected error" in result.findings[0]["message"].lower()

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_missing_or_non_string_verdict_fails_closed(
        self,
        adapter: Provider03NormativeProvider,
    ) -> None:
        """Missing or non-string verdict fails closed without AttributeError."""
        # Test with None verdict
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            mock_response = _mock_response({"verdict": None})
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        assert result.admitted is False
        # No AttributeError should be raised

        # Test with integer verdict
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            mock_response = _mock_response({"verdict": 12345})
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        assert result.admitted is False
        # No AttributeError should be raised

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_non_list_findings_handled_safely(
        self,
        adapter: Provider03NormativeProvider,
    ) -> None:
        """Non-list findings are handled gracefully without TypeError."""
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            mock_response = _mock_response(
                {"verdict": "ESCALATE", "findings": "not-a-list"}
            )
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria({"action": "test"})

        # Should parse gracefully without TypeError
        assert result.admitted is False
        # Findings defaults to empty list when non-list value provided
        # The escalate marker should still be injected
        assert any(f["code"] == "provider_03.escalate" for f in result.findings)

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_submit_evidence_handles_json_decode_error(
        self,
        adapter: Provider03NormativeProvider,
    ) -> None:
        """submit_evidence handles JSONDecodeError gracefully."""
        import json

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_response.json.side_effect = json.JSONDecodeError(
                "Expecting value", "doc", 0
            )
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            seal = await adapter.submit_evidence("thread-789", "hash-abc")

        assert seal.thread_id == "thread-789"
        assert seal.error is not None
        assert "Invalid JSON response" in seal.error
        # No exception should leak

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_submit_evidence_handles_non_dict_response(
        self,
        adapter: Provider03NormativeProvider,
    ) -> None:
        """submit_evidence handles non-dict response gracefully."""
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            mock_response = MagicMock()
            mock_response.raise_for_status = MagicMock()
            mock_response.json.return_value = ["seal123"]
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            seal = await adapter.submit_evidence("thread-789", "hash-abc")

        assert seal.thread_id == "thread-789"
        assert seal.error is not None
        assert "expected JSON object" in seal.error
        # No exception should leak


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
# Action Context Collision Tests (Invariant I-07)
# ---------------------------------------------------------------------------


class TestActionContextCollision:
    """Tests for Invariant I-07 action context collision handling.

    Invariant I-07 requires that any collision between configured `src_key` and
    `dest_key` inside `action_context` immediately short-circuits with
    `admitted=False`, produces a `MAPPING_COLLISION` finding, and completely
    prevents wire dispatch.
    """

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_collision_rejects_without_dispatch(self) -> None:
        """Collision between src_key and dest_key blocks dispatch entirely."""
        adapter = Provider03NormativeProvider(
            endpoint="http://localhost:8080",
            action_context_field_map={"amount": "magnitude"},
        )

        # Payload with BOTH legacy key 'amount' and canonical key 'magnitude'
        payload = {
            "action": "test_action",
            "action_context": {
                "amount": 1000,
                "magnitude": 2000,
            },
        }

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(payload)

            # Assert HTTP client was NEVER invoked (short-circuit before dispatch)
            client_instance.post.assert_not_called()

        # Assert fail-closed with MAPPING_COLLISION
        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "MAPPING_COLLISION"
        assert result.findings[0]["severity"] == "blocked"
        assert "amount" in result.findings[0]["message"]
        assert "magnitude" in result.findings[0]["message"]
        assert result.findings[0]["source_key"] == "amount"
        assert result.findings[0]["destination_key"] == "magnitude"

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_collision_rejects_even_if_values_match(self) -> None:
        """Collision fails closed even when src and dest values are identical.

        Value equality must not bypass schema determinism — the presence of both
        keys itself violates the invariant.
        """
        adapter = Provider03NormativeProvider(
            endpoint="http://localhost:8080",
            action_context_field_map={"amount": "magnitude"},
        )

        # Payload where both keys exist with IDENTICAL values
        payload = {
            "action": "test_action",
            "action_context": {
                "amount": 1000,
                "magnitude": 1000,  # Same value as 'amount'
            },
        }

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            MockClient.return_value.__aenter__.return_value = client_instance

            result = await adapter.validate_fria(payload)

            # Assert HTTP client was NEVER invoked
            client_instance.post.assert_not_called()

        # Assert fail-closed with MAPPING_COLLISION (value equality is irrelevant)
        assert result.admitted is False
        assert len(result.findings) == 1
        assert result.findings[0]["code"] == "MAPPING_COLLISION"
        assert result.findings[0]["severity"] == "blocked"

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_mapping_succeeds_when_only_legacy_key_present(self) -> None:
        """Field mapping proceeds when only src_key is present (no collision)."""
        adapter = Provider03NormativeProvider(
            endpoint="http://localhost:8080",
            action_context_field_map={"amount": "magnitude"},
        )

        # Payload with ONLY legacy key 'amount' (canonical key 'magnitude' absent)
        payload = {
            "action": "test_action",
            "action_context": {
                "amount": 1000,
            },
        }

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

            result = await adapter.validate_fria(payload)

            # Assert HTTP client was invoked exactly once
            client_instance.post.assert_called_once()

            # Inspect the dispatched payload
            call_args = client_instance.post.call_args
            dispatched_payload = call_args.kwargs["json"]

            # Assert 'amount' was mapped to 'magnitude' and 'amount' was removed
            assert "magnitude" in dispatched_payload["action_context"]
            assert dispatched_payload["action_context"]["magnitude"] == 1000
            assert "amount" not in dispatched_payload["action_context"]

        # Assert admission succeeded
        assert result.admitted is True
        assert result.findings == []

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_mapping_succeeds_when_only_canonical_key_present(self) -> None:
        """Dispatch proceeds normally when only dest_key is present (no mapping needed)."""
        adapter = Provider03NormativeProvider(
            endpoint="http://localhost:8080",
            action_context_field_map={"amount": "magnitude"},
        )

        # Payload with ONLY canonical key 'magnitude' (legacy key 'amount' absent)
        payload = {
            "action": "test_action",
            "action_context": {
                "magnitude": 1000,
            },
        }

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

            result = await adapter.validate_fria(payload)

            # Assert HTTP client was invoked
            client_instance.post.assert_called_once()

            # Inspect the dispatched payload
            call_args = client_instance.post.call_args
            dispatched_payload = call_args.kwargs["json"]

            # Assert 'magnitude' remains unchanged (no mapping applied)
            assert "magnitude" in dispatched_payload["action_context"]
            assert dispatched_payload["action_context"]["magnitude"] == 1000
            assert "amount" not in dispatched_payload["action_context"]

        # Assert admission succeeded
        assert result.admitted is True
        assert result.findings == []

    @pytest.mark.asyncio
    @pytest.mark.local
    async def test_field_map_identity_no_op(self) -> None:
        """Identity mapping (src_key == dest_key) does NOT trigger self-collision."""
        adapter = Provider03NormativeProvider(
            endpoint="http://localhost:8080",
            action_context_field_map={"currency": "currency"},  # Identity mapping
        )

        # Payload with identity-mapped key
        payload = {
            "action": "test_action",
            "action_context": {
                "currency": "USD",
            },
        }

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

            result = await adapter.validate_fria(payload)

            # Assert HTTP client was invoked (no collision detected)
            client_instance.post.assert_called_once()

        # Assert admission succeeded (identity mapping is a no-op, not a collision)
        assert result.admitted is True
        assert result.findings == []
        assert result.error is None


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
