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
test_provider_01_phase3_schema.py — FlowSignal Phase 3 v0.2 Schema Tests
=========================================================================

Validates the 37-field CageAuthorityDetermineRequest payload mapping
and /cage/validate endpoint cutover.

See: docs/partners/FLOWSIGNAL_PHASE3_V02_SCHEMA.md § 2
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.integrations.provider_01.provider import (
    FlowSignalNormativeProvider,
    _build_cage_authority_request,
)

# Hermetic: tests FlowSignal adapter with mocks, no live services.
pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.partner]


# ---------------------------------------------------------------------------
# Schema Validation Tests (Phase 3 v0.2)
# ---------------------------------------------------------------------------


class TestPhase3SchemaMapping:
    """Tests for the 37-field CageAuthorityDetermineRequest payload."""

    def test_build_cage_authority_request_maps_all_37_fields(self) -> None:
        """_build_cage_authority_request produces complete 37-field payload."""
        envelope = {
            "correlation_id": "exec-123",
            "thread_id": "thread-456",
            "action": "payment.release",
            "target": "TREASURY_GATEWAY",
            "operator_urn": "agent-treasury-01",
            "approval_id": "approval-789",
            "params": {
                "amount": 750000.0,
                "currency": "GBP",
                "symbol": "Invoice 78431",
                "purpose": "Invoice payment",
                "source_account": "TREASURY-001",
                "beneficiary": "SUPPLIER-X",
                "counterparty_status": "APPROVED",
                "account_status": "ACTIVE",
                "risk_state": "NORMAL",
                "screening_status": "CLEAR",
                "screening_captured_at": "2026-08-10T09:00:00Z",
                "screening_max_age_seconds": 3600,
                "screening_source": "SCREENING-SERVICE-01",
                "mandate_id": "MANDATE-001",
                "mandate_max_amount": 1000000.0,
                "permitted_source_accounts": ["TREASURY-001"],
                "permitted_counterparty_class": "APPROVED_SUPPLIERS",
                "mandate_valid_until": "2026-12-31T23:59:59Z",
                "principal_id": "institution-001",
                "principal_name": "Example Financial Institution",
                "actor_role": "treasury_agent",
                "approval_required": False,
                "requested_execution_time": "2026-08-10T09:15:00Z",
            },
        }

        payload = _build_cage_authority_request(envelope)

        # Verify all 37 fields are present
        assert len(payload) == 37

        # Core Request Identifiers (3 fields)
        assert payload["approval_id"] == "approval-789"
        assert payload["platform"] == "GOOGLE-CAGE-REFERENCE"
        assert payload["execution_id"] == "exec-123"

        # Scenario & Action Context (4 fields)
        assert payload["scenario_id"] == "thread-456"
        assert payload["action"] == "payment.release"
        assert payload["target"] == "TREASURY_GATEWAY"
        assert payload["context"] == "Invoice 78431"

        # Actor Identity & Authorization (5 fields)
        assert payload["actor_id"] == "agent-treasury-01"
        assert payload["actor_type"] == "autonomous_agent"
        assert payload["actor_role"] == "treasury_agent"
        assert payload["actor_authenticated"] is True
        assert payload["kya_status"] == "VERIFIED"

        # Principal (2 fields)
        assert payload["principal_id"] == "institution-001"
        assert payload["principal_name"] == "Example Financial Institution"

        # Mandate Boundary & Limits (7 fields)
        assert payload["mandate_id"] == "MANDATE-001"
        assert payload["mandate_status"] == "ACTIVE"
        assert payload["mandate_max_amount"] == 1000000.0
        assert payload["mandate_currency"] == "GBP"
        assert payload["permitted_source_accounts"] == ["TREASURY-001"]
        assert payload["permitted_counterparty_class"] == "APPROVED_SUPPLIERS"
        assert payload["mandate_valid_until"] == "2026-12-31T23:59:59Z"

        # Proposed Transaction Details (5 fields)
        assert payload["magnitude"] == 750000.0
        assert payload["currency"] == "GBP"
        assert payload["source_account"] == "TREASURY-001"
        assert payload["beneficiary"] == "SUPPLIER-X"
        assert payload["purpose"] == "Invoice payment"

        # Runtime State & Risk Context (4 fields)
        assert payload["counterparty_status"] == "APPROVED"
        assert payload["account_status"] == "ACTIVE"
        assert payload["risk_state"] == "NORMAL"
        assert payload["approval_required"] is False

        # Mutable Evidence Freshness (4 fields)
        assert payload["screening_status"] == "CLEAR"
        assert payload["screening_captured_at"] == "2026-08-10T09:00:00Z"
        assert payload["screening_max_age_seconds"] == 3600
        assert payload["screening_source"] == "SCREENING-SERVICE-01"

        # Execution Timing (1 field)
        assert payload["requested_execution_time"] == "2026-08-10T09:15:00Z"

        # Optional Fields (2 fields)
        assert payload["authority_resolution_path"] is None
        assert len(payload["evidence_references"]) == 1
        assert payload["evidence_references"][0]["type"] == "governance_decision"
        assert payload["evidence_references"][0]["uri"] == "cer://exec-123"

    def test_build_cage_authority_request_applies_defaults(self) -> None:
        """_build_cage_authority_request applies correct defaults for missing fields."""
        minimal_envelope = {
            "correlation_id": "exec-minimal",
            "thread_id": "thread-minimal",
            "action": "test.action",
            "target": "TEST_TARGET",
            "operator_urn": "agent-test",
            "params": {},
        }

        payload = _build_cage_authority_request(minimal_envelope)

        # Verify defaults per schema spec
        assert payload["approval_id"] == "exec-minimal"  # fallback to correlation_id
        assert payload["platform"] == "GOOGLE-CAGE-REFERENCE"
        assert payload["context"] == ""  # empty when no symbol/purpose
        assert payload["actor_type"] == "autonomous_agent"
        assert payload["actor_role"] == "agent"
        assert payload["actor_authenticated"] is True
        assert payload["kya_status"] == "VERIFIED"
        assert payload["principal_id"] == "cage-default"
        assert payload["principal_name"] == "CAGE Platform"
        assert payload["mandate_id"] == "DEFAULT-MANDATE"
        assert payload["mandate_status"] == "ACTIVE"
        assert payload["mandate_max_amount"] == 1000000.0
        assert payload["mandate_currency"] == "USD"
        assert payload["permitted_source_accounts"] == ["DEFAULT"]
        assert payload["permitted_counterparty_class"] == "UNRESTRICTED"
        assert payload["mandate_valid_until"] == "2099-12-31T23:59:59Z"
        assert payload["magnitude"] == 0.0
        assert payload["currency"] == "USD"
        assert payload["source_account"] == "DEFAULT"
        assert payload["beneficiary"] == "UNKNOWN"
        assert payload["purpose"] == "CAGE transaction"
        assert payload["counterparty_status"] == "UNKNOWN"
        assert payload["account_status"] == "ACTIVE"
        assert payload["risk_state"] == "NORMAL"
        assert payload["approval_required"] is False
        assert payload["screening_status"] == "CLEAR"
        assert payload["screening_max_age_seconds"] == 3600
        assert payload["screening_source"] == "CAGE-INTERNAL"
        assert payload["authority_resolution_path"] is None

        # Verify datetime fields are ISO 8601 format
        assert isinstance(payload["screening_captured_at"], str)
        assert "T" in payload["screening_captured_at"]
        assert isinstance(payload["requested_execution_time"], str)
        assert "T" in payload["requested_execution_time"]

    @pytest.mark.asyncio
    async def test_validate_fria_sends_37_field_payload_to_cage_validate_endpoint(
        self,
    ) -> None:
        """validate_fria sends full 37-field payload to /cage/validate."""
        adapter = FlowSignalNormativeProvider(
            endpoint="http://localhost:8080",
            api_key="test-key",
            timeout=5.0,
        )

        mock_response = MagicMock()
        # Return REFUSE to avoid consequence token minting complexity in this test
        mock_response.json.return_value = {
            "decision": "REFUSE",
            "message": "Test refusal",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            # Minimal envelope
            envelope = {
                "correlation_id": "exec-123",
                "thread_id": "thread-456",
                "action": "test.action",
                "target": "TEST",
                "operator_urn": "agent-1",
                "params": {"amount": 100.0, "currency": "USD"},
            }

            with patch(
                "src.integrations.provider_01.provider._VALIDATE_PATH",
                "/cage/validate",
            ):
                result = await adapter.validate_fria(envelope)
                # Verify REFUSE was processed correctly
                assert result.admitted is False
                assert len(result.findings) == 1
                assert result.findings[0]["code"] == "FLOWSIGNAL_REFUSE"

            # Verify the endpoint was called with /cage/validate
            assert client_instance.post.called
            call_args = client_instance.post.call_args
            assert "/cage/validate" in call_args[0][0]

            # Verify the payload has 37 fields
            sent_payload = call_args[1]["json"]
            assert len(sent_payload) == 37

            # Spot-check required fields
            assert sent_payload["execution_id"] == "exec-123"
            assert sent_payload["platform"] == "GOOGLE-CAGE-REFERENCE"
            assert sent_payload["magnitude"] == 100.0
            assert sent_payload["currency"] == "USD"
            assert sent_payload["actor_id"] == "agent-1"


# ---------------------------------------------------------------------------
# Endpoint Cutover Tests
# ---------------------------------------------------------------------------


class TestEndpointCutover:
    """Tests for Phase 3 v0.2 endpoint cutover to /cage/validate."""

    @pytest.mark.asyncio
    async def test_validate_fria_uses_cage_validate_endpoint_by_default(self) -> None:
        """validate_fria targets /cage/validate by default."""
        adapter = FlowSignalNormativeProvider(
            endpoint="http://localhost:8080",
            api_key="test-key",
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {"decision": "REFUSE"}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            await adapter.validate_fria({"correlation_id": "test"})

            # Verify /cage/validate was called
            call_args = client_instance.post.call_args
            assert call_args[0][0] == "http://localhost:8080/cage/validate"

    @pytest.mark.asyncio
    async def test_validate_fria_respects_validate_path_override(self) -> None:
        """validate_fria respects CAGE_NORMATIVE_VALIDATE_PATH override."""
        adapter = FlowSignalNormativeProvider(
            endpoint="http://localhost:8080",
            api_key="test-key",
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {"decision": "REFUSE"}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post.return_value = mock_response
            MockClient.return_value.__aenter__.return_value = client_instance

            # Override the path
            with patch(
                "src.integrations.provider_01.provider._VALIDATE_PATH",
                "/custom/validate",
            ):
                await adapter.validate_fria({"correlation_id": "test"})

            # Verify custom path was used
            call_args = client_instance.post.call_args
            assert call_args[0][0] == "http://localhost:8080/custom/validate"
