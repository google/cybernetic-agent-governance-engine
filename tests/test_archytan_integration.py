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

"""Unit tests for Archytan integration (AttestationProvider & EnvelopeMapper)."""

import pytest
from src.integrations.archytan import (
    ArchytanAttestationProvider,
    ArchytanEnvelopeMapper,
)
from src.gateway.governance.governance_envelope import (
    AttestationStatus,
    ExternalAttestation,
    GovernanceEnvelopeBuilder,
)


@pytest.mark.asyncio
async def test_archytan_provider_properties_and_unconfigured_fetch():
    """Verify provider name and unconfigured endpoint behavior."""
    provider = ArchytanAttestationProvider()
    assert provider.provider_name == "archytan"

    # With no endpoint configured, returns empty list
    attestations = await provider.fetch_attestations({})
    assert attestations == []


@pytest.mark.asyncio
async def test_archytan_provider_stub_fetch():
    """Verify provider returns empty list when stub endpoint is set."""
    provider = ArchytanAttestationProvider(endpoint="https://archytan.example.com")
    attestations = await provider.fetch_attestations({"action": "execute_trade"})
    assert attestations == []


def test_archytan_envelope_mapper_to_and_from_format():
    """Verify bidirectional mapping fidelity between GovernanceEnvelope and Archytan format."""
    builder = GovernanceEnvelopeBuilder()
    att = ExternalAttestation(
        attestation_type="BLUEPRINT",
        status=AttestationStatus.VERIFIED.value,
        receipt_id="archytan-rec-001",
        attested_at="2026-08-22T08:00:00.000Z",
        metadata={"threshold_id": "THR-FIN-006"},
    )
    envelope = builder.build_unsigned(
        action="execute_treasury_transfer",
        params={"amount": 25000.0, "currency": "USD"},
        governance_result={"verdict": "ALLOW"},
        external_attestations=[att],
    )

    mapper = ArchytanEnvelopeMapper()
    archytan_payload = mapper.to_archytan_format(envelope)

    # Verify outer Archytan envelope schema
    assert archytan_payload["archytan_version"] == "1.0"
    assert archytan_payload["digest"] == envelope.compute_digest_hex()
    assert archytan_payload["metadata"]["envelope_id"] == envelope.envelope_id
    assert archytan_payload["metadata"]["envelope_version"] == "2.1"
    assert archytan_payload["metadata"]["attestation_count"] == 1
    assert "cage_envelope" in archytan_payload

    # Reconstruct from Archytan format
    reconstructed = mapper.from_archytan_format(archytan_payload)
    assert reconstructed.envelope_id == envelope.envelope_id
    assert reconstructed.envelope_version == "2.1"
    assert len(reconstructed.external_attestations) == 1
    assert reconstructed.external_attestations[0].attestation_type == "BLUEPRINT"
    assert reconstructed.external_attestations[0].metadata["threshold_id"] == "THR-FIN-006"
    assert reconstructed.compute_digest() == envelope.compute_digest()


def test_archytan_envelope_mapper_invalid_payload_raises():
    """Verify from_archytan_format raises ValueError if cage_envelope is missing."""
    mapper = ArchytanEnvelopeMapper()
    with pytest.raises(ValueError, match="missing 'cage_envelope'"):
        mapper.from_archytan_format({"archytan_version": "1.0"})

