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

"""Unit tests for Provider 04 integration (AttestationProvider & EnvelopeMapper)."""

import pytest

from src.gateway.governance.governance_envelope import (
    AttestationStatus,
    ExternalAttestation,
    GovernanceEnvelopeBuilder,
)
from src.integrations.provider_04 import (
    Provider04AttestationProvider,
    Provider04EnvelopeMapper,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.mark.asyncio
async def test_provider_04_properties_and_unconfigured_fetch():
    """Verify provider name and unconfigured endpoint behavior."""
    provider = Provider04AttestationProvider()
    assert provider.provider_name == "provider_04"

    # With no endpoint configured, returns empty list
    attestations = await provider.fetch_attestations({})
    assert attestations == []


@pytest.mark.asyncio
async def test_provider_04_stub_fetch():
    """Verify provider returns empty list when stub endpoint is set."""
    provider = Provider04AttestationProvider(endpoint="https://provider04.example.com")
    attestations = await provider.fetch_attestations({"action": "execute_trade"})
    assert attestations == []


def test_provider_04_envelope_mapper_to_and_from_format():
    """Verify bidirectional mapping fidelity between GovernanceEnvelope and Provider 04 format."""
    builder = GovernanceEnvelopeBuilder()
    att = ExternalAttestation(
        attestation_type="BLUEPRINT",
        status=AttestationStatus.VERIFIED.value,
        receipt_id="provider04-rec-001",
        attested_at="2026-08-22T08:00:00.000Z",
        metadata={"threshold_id": "THR-FIN-006"},
    )
    envelope = builder.build_unsigned(
        action="execute_treasury_transfer",
        params={"amount": 25000.0, "currency": "USD"},
        governance_result={"verdict": "ALLOW"},
        external_attestations=[att],
    )

    mapper = Provider04EnvelopeMapper()
    provider_04_payload = mapper.to_provider_04_format(envelope)

    # Verify outer Provider 04 envelope schema
    assert provider_04_payload["provider_04_version"] == "1.0"
    assert provider_04_payload["digest"] == envelope.compute_digest_hex()
    assert provider_04_payload["metadata"]["envelope_id"] == envelope.envelope_id
    assert provider_04_payload["metadata"]["envelope_version"] == "2.1"
    assert provider_04_payload["metadata"]["attestation_count"] == 1
    assert "cage_envelope" in provider_04_payload

    # Reconstruct from Provider 04 format
    reconstructed = mapper.from_provider_04_format(provider_04_payload)
    assert reconstructed.envelope_id == envelope.envelope_id
    assert reconstructed.envelope_version == "2.1"
    assert len(reconstructed.external_attestations) == 1
    assert reconstructed.external_attestations[0].attestation_type == "BLUEPRINT"
    assert (
        reconstructed.external_attestations[0].metadata["threshold_id"] == "THR-FIN-006"
    )
    assert reconstructed.compute_digest() == envelope.compute_digest()


def test_provider_04_envelope_mapper_invalid_payload_raises():
    """Verify from_provider_04_format raises ValueError if cage_envelope is missing."""
    mapper = Provider04EnvelopeMapper()
    with pytest.raises(ValueError, match="missing 'cage_envelope'"):
        mapper.from_provider_04_format({"provider_04_version": "1.0"})
