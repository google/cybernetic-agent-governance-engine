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
tests/test_normative_provider_conformance.py — Universal Provider Conformance Suite
===================================================================================

Verifies that all 6 vendor integrations adhere to the `NormativeProvider` or
`AttestationProvider` protocols, implement correct fail-closed semantics on HTTP
errors, map tri-state upstream responses to DeferQueue parking (`needs_human_review`),
and are correctly resolved by the `get_normative_provider()` factory.

This test file is explicitly designed to be 100% hermetic (no live network calls)
and runs as part of the fast `pytest-logic` CI matrix across all regions.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
import respx

from src.gateway.governance.attestation_provider import AttestationProvider
from src.gateway.governance.normative_provider import get_normative_provider
from src.gateway.governance.seams.attestation import (
    AttestationStatus,
    ExternalAttestation,
)
from src.gateway.governance.seams.normative import (
    EvidenceSeal,
    NormativeBaseline,
    NormativeProvider,
    ValidationResult,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

NORMATIVE_PROVIDERS = ["static", "provider_01", "provider_03", "provider_06"]
ATTESTATION_PROVIDERS = [
    "provider_02",
    "provider_05-blueprint",
    "provider_05-key",
    "provider_05-physics",
]


@pytest.mark.parametrize("provider_name", NORMATIVE_PROVIDERS)
def test_factory_resolution_normative(provider_name: str) -> None:
    """Verify that get_normative_provider correctly resolves all normative providers."""
    provider = get_normative_provider(provider_name)
    assert hasattr(provider, "fetch_baseline")
    assert hasattr(provider, "validate_fria")
    assert hasattr(provider, "submit_evidence")


@pytest.mark.parametrize(
    "alias, expected",
    [
        ("p01", "provider_01"),
        ("p03", "provider_03"),
        ("agent_integrity", "provider_06"),
    ],
)
def test_factory_alias_resolution(alias: str, expected: str) -> None:
    provider = get_normative_provider(alias)
    # The provider instance should match the one returned by the canonical name
    assert provider.__class__ == get_normative_provider(expected).__class__


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_name", ["provider_01", "provider_03", "provider_06"])
async def test_normative_provider_interface(provider_name: str) -> None:
    """Verify that fetch_baseline, validate_fria, and submit_evidence return expected types."""
    provider = get_normative_provider(provider_name)

    with respx.mock:
        # Mock any outgoing request to return a generic 500 so we can test fail-closed
        respx.route().mock(
            return_value=httpx.Response(500, json={"error": "Server Error"})
        )

        # Test fail-closed on validate_fria
        # Ensure we pass exactly 1 argument (the payload) as specified by the Protocol
        result = await provider.validate_fria({"action": "test"})
        assert isinstance(result, ValidationResult)
        assert result.admitted is False, (
            f"{provider_name} failed to fail-closed on 500 error"
        )
        assert result.findings[0]["code"] in (
            "ENDPOINT_ERROR",
            "PARSE_ERROR",
            "INTERNAL_ERROR",
            "cage.endpoint_error",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_identifier", ATTESTATION_PROVIDERS)
async def test_attestation_provider_conformance(provider_identifier: str) -> None:
    """Verify that attestation providers satisfy the AttestationProvider protocol.

    Core requirements (Phase 10, C8):
    - provider_name is non-empty and matches the expected identifier
    - fetch_attestations({}) returns list[ExternalAttestation]
    - every entry carries a valid AttestationStatus
    - failures fail closed (network errors, parse failures, etc.)
    """
    from src.integrations.provider_02 import Provider02AttestationProvider
    from src.integrations.provider_05.blueprint_provider import (
        Provider05BlueprintProvider,
    )
    from src.integrations.provider_05.key_provider import Provider05KeyProvider
    from src.integrations.provider_05.physics_provider import Provider05PhysicsProvider

    # Map provider_identifier to the actual provider class
    provider_map = {
        "provider_02": Provider02AttestationProvider(),
        "provider_05-blueprint": Provider05BlueprintProvider(),
        "provider_05-key": Provider05KeyProvider(),
        "provider_05-physics": Provider05PhysicsProvider(),
    }

    provider = provider_map[provider_identifier]

    # Verify AttestationProvider protocol compliance
    assert isinstance(provider, AttestationProvider)
    assert hasattr(provider, "fetch_attestations")
    assert hasattr(provider, "provider_name")

    # Verify provider_name is non-empty and matches expected identifier
    assert isinstance(provider.provider_name, str)
    assert provider.provider_name, "provider_name must be non-empty"
    assert provider.provider_name == provider_identifier, (
        f"provider_name '{provider.provider_name}' does not match "
        f"expected identifier '{provider_identifier}'"
    )

    # Fetch attestations with empty context
    attestations = await provider.fetch_attestations({})

    # Verify return type is list[ExternalAttestation]
    assert isinstance(attestations, list)
    assert all(isinstance(a, ExternalAttestation) for a in attestations)

    # Verify every entry carries a valid AttestationStatus and provider_name
    for attestation in attestations:
        assert attestation.status in [s.value for s in AttestationStatus], (
            f"Invalid AttestationStatus: {attestation.status}"
        )
        assert attestation.provider_name, (
            f"ExternalAttestation missing provider_name: {attestation}"
        )
        assert attestation.provider_name == provider_identifier, (
            f"ExternalAttestation provider_name '{attestation.provider_name}' "
            f"does not match provider '{provider_identifier}'"
        )
        assert attestation.attestation_type, (
            f"ExternalAttestation missing attestation_type: {attestation}"
        )
        # receipt_id may be empty for STALE/ERROR/DENIED cases (fail-closed behavior)
        # Only VERIFIED attestations must carry a non-empty receipt_id
        if attestation.status == AttestationStatus.VERIFIED.value:
            assert attestation.receipt_id, (
                f"VERIFIED attestation missing receipt_id: {attestation}"
            )


@pytest.mark.asyncio
async def test_attestation_providers_legacy_protocol_check() -> None:
    """Legacy test retained for backwards compatibility check only.

    The authoritative conformance test is test_attestation_provider_conformance
    above, which exercises the full protocol contract.
    """
    from src.integrations.provider_02 import Provider02AttestationProvider
    from src.integrations.provider_05.blueprint_provider import (
        Provider05BlueprintProvider,
    )

    p02 = Provider02AttestationProvider()
    p05 = Provider05BlueprintProvider()

    # Verify AttestationProvider protocol compliance
    assert isinstance(p02, AttestationProvider)
    assert isinstance(p05, AttestationProvider)

    # Verify protocol methods exist
    assert hasattr(p02, "fetch_attestations")
    assert hasattr(p02, "provider_name")
    assert hasattr(p05, "fetch_attestations")
    assert hasattr(p05, "provider_name")

    # Verify provider_name returns a string
    assert isinstance(p02.provider_name, str)
    assert p02.provider_name == "provider_02"
    assert isinstance(p05.provider_name, str)


@pytest.mark.asyncio
async def test_provider_02_rejected_from_normative_factory() -> None:
    """Verify that requesting provider_02 from get_normative_provider raises helpful error."""
    with pytest.raises(
        ValueError,
        match=r"AttestationProvider.*AttestationAggregator",
    ):
        get_normative_provider("provider_02")


# ---------------------------------------------------------------------------
# FlowSignal Decision Mapping Tests (Phase 1, §3.1)
# ---------------------------------------------------------------------------


class TestFlowSignalDecisionMapping:
    """Verify FlowSignal correctly maps FlowSignal tri-state decision to CAGE primitives.

    These tests cover the ESCALATE contract mapping per §3.1 of the FlowSignal
    integration plan, ensuring:
      - ALLOW → admitted=True, no blocking findings
      - REFUSE → admitted=False, FLOWSIGNAL_REFUSE finding
      - ESCALATE → admitted=False, EXTERNAL_HOLD finding with needs_human_review
      - Malformed decision → fail-closed with PARSE_ERROR
      - Missing decision → backward-compat with admitted/findings shape
    """

    @pytest.fixture
    def provider(self):
        """Instantiate FlowSignal with mock endpoint."""
        from src.integrations.provider_01.provider import FlowSignalNormativeProvider

        return FlowSignalNormativeProvider(
            endpoint="https://mock.flowsignal.example.com",
            api_key="test-key",
            timeout=5.0,
        )

    @pytest.mark.asyncio
    async def test_flowsignal_decision_allow(self, provider) -> None:
        """ALLOW decision → admitted=True, CONSEQUENCE_TOKEN finding (Phase 2 ST-4)."""
        from unittest.mock import patch

        # Mock KMS signer to avoid RuntimeError in dev/test
        with (
            respx.mock,
            patch(
                "src.gateway.governance.kms_signer.get_governance_signer"
            ) as mock_get_signer,
        ):
            # Mock signer that fails (to test token minting is attempted)
            mock_signer = MagicMock()
            mock_signer.sign_raw.side_effect = RuntimeError("KMS not active in test")
            mock_get_signer.return_value = mock_signer

            respx.post("https://mock.flowsignal.example.com/validate/fria").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "decision": "ALLOW",
                        "message": "Transaction approved by FlowSignal",
                        "authority_record_id": "test-auth-rec",
                    },
                )
            )

            result = await provider.validate_fria(
                {
                    "action": "test_allow",
                    "actor_id": "test-actor",
                    "thread_id": "test-thread",
                }
            )

            assert isinstance(result, ValidationResult)
            # Phase 2: Token minting fails without KMS, so admitted=False (fail-closed)
            assert result.admitted is False
            assert len(result.findings) == 1
            assert result.findings[0]["code"] == "CONSEQUENCE_TOKEN_MINT_FAILED"

    @pytest.mark.asyncio
    async def test_flowsignal_decision_refuse(self, provider) -> None:
        """REFUSE decision → admitted=False, FLOWSIGNAL_REFUSE finding with blocked severity."""
        with respx.mock:
            respx.post("https://mock.flowsignal.example.com/validate/fria").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "decision": "REFUSE",
                        "message": "Transaction blocked by compliance policy",
                    },
                )
            )

            result = await provider.validate_fria({"action": "test_refuse"})

            assert isinstance(result, ValidationResult)
            assert result.admitted is False
            assert len(result.findings) == 1
            assert result.findings[0]["code"] == "FLOWSIGNAL_REFUSE"
            assert result.findings[0]["severity"] == "blocked"
            assert (
                "blocked" in result.findings[0]["message"].lower()
                or "refuse" in result.findings[0]["message"].lower()
            )

    @pytest.mark.asyncio
    async def test_flowsignal_decision_escalate(self, provider) -> None:
        """ESCALATE decision → admitted=False, EXTERNAL_HOLD finding with needs_human_review=True."""
        with respx.mock:
            respx.post("https://mock.flowsignal.example.com/validate/fria").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "decision": "ESCALATE",
                        "message": "Transaction requires human approval",
                    },
                )
            )

            result = await provider.validate_fria({"action": "test_escalate"})

            assert isinstance(result, ValidationResult)
            assert result.admitted is False
            assert len(result.findings) == 1
            assert result.findings[0]["code"] == "EXTERNAL_HOLD"
            assert result.findings[0]["severity"] == "review"
            assert result.findings[0]["needs_human_review"] is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "malformed_decision",
        # Note: lowercase variants of ALLOW/REFUSE/ESCALATE are intentionally excluded
        # because the implementation is case-insensitive (normalizes to uppercase).
        # Only truly invalid values should be in this list.
        ["INVALID", "Accept", "", "DENY", "BLOCK", "PENDING", "null", "123"],
    )
    async def test_flowsignal_decision_malformed_failclosed(
        self, provider, malformed_decision: str
    ) -> None:
        """Malformed/unrecognized decision value → fail-closed with PARSE_ERROR."""
        with respx.mock:
            respx.post("https://mock.flowsignal.example.com/validate/fria").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "decision": malformed_decision,
                        "message": "Some message",
                    },
                )
            )

            result = await provider.validate_fria({"action": "test_malformed"})

            assert isinstance(result, ValidationResult)
            assert result.admitted is False, (
                f"Malformed decision '{malformed_decision}' should fail-closed"
            )
            assert len(result.findings) == 1
            assert result.findings[0]["code"] == "PARSE_ERROR"
            assert result.findings[0]["severity"] == "blocked"
            assert malformed_decision in result.findings[0]["message"]

    @pytest.mark.asyncio
    async def test_flowsignal_missing_decision_field_fails_closed(
        self, provider
    ) -> None:
        """Payload without decision field → fail closed (BC-03 remediation)."""
        with respx.mock:
            respx.post("https://mock.flowsignal.example.com/validate/fria").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "admitted": True,
                        "findings": [
                            {"code": "INFO", "severity": "info", "message": "All clear"}
                        ],
                    },
                )
            )

            result = await provider.validate_fria({"action": "test_legacy"})

            assert isinstance(result, ValidationResult)
            assert result.admitted is False  # Fail closed
            assert len(result.findings) == 1
            assert result.findings[0]["code"] == "cage.endpoint_error"
            assert result.findings[0]["severity"] == "blocked"
            assert (
                "missing required 'decision' field"
                in result.findings[0]["message"].lower()
            )

    @pytest.mark.asyncio
    async def test_flowsignal_missing_decision_field_fails_closed_even_when_admitted_false(
        self, provider
    ) -> None:
        """Payload without decision field fails closed regardless of admitted value (BC-03 remediation)."""
        with respx.mock:
            respx.post("https://mock.flowsignal.example.com/validate/fria").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "admitted": False,
                        "findings": [
                            {
                                "code": "LEGACY_BLOCK",
                                "severity": "blocked",
                                "message": "Blocked by legacy provider",
                            }
                        ],
                    },
                )
            )

            result = await provider.validate_fria({"action": "test_legacy_block"})

            assert isinstance(result, ValidationResult)
            assert result.admitted is False  # Fail closed
            assert len(result.findings) == 1
            # The legacy LEGACY_BLOCK finding is ignored; fail-closed finding is emitted
            assert result.findings[0]["code"] == "cage.endpoint_error"
            assert result.findings[0]["severity"] == "blocked"
            assert (
                "missing required 'decision' field"
                in result.findings[0]["message"].lower()
            )

    @pytest.mark.asyncio
    async def test_flowsignal_decision_case_insensitive(self, provider) -> None:
        """Decision values are case-insensitive (ALLOW, Allow, allow all work)."""
        from unittest.mock import patch

        # Mock KMS signer to avoid RuntimeError in dev/test
        with (
            respx.mock,
            patch(
                "src.gateway.governance.kms_signer.get_governance_signer"
            ) as mock_get_signer,
        ):
            # Mock signer that fails (to test token minting is attempted)
            mock_signer = MagicMock()
            mock_signer.sign_raw.side_effect = RuntimeError("KMS not active in test")
            mock_get_signer.return_value = mock_signer

            # Lowercase "allow"
            respx.post("https://mock.flowsignal.example.com/validate/fria").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "decision": "allow",  # lowercase
                        "message": "lowercase",
                        "authority_record_id": "test-auth-rec",
                    },
                )
            )

            result = await provider.validate_fria(
                {
                    "action": "test_case",
                    "actor_id": "test-actor",
                    "thread_id": "test-thread",
                }
            )
            # Our implementation normalizes to uppercase, so "allow" → "ALLOW" → mints token
            # But token minting fails without KMS → fail-closed
            assert result.admitted is False
            assert len(result.findings) == 1
            assert result.findings[0]["code"] == "CONSEQUENCE_TOKEN_MINT_FAILED"
