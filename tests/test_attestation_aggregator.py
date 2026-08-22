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

"""Unit tests for AttestationProvider and AttestationAggregator."""

import asyncio
from typing import Any

import pytest

from src.gateway.governance.attestation_aggregator import AttestationAggregator
from src.gateway.governance.attestation_provider import AttestationProvider
from src.gateway.governance.governance_envelope import (
    AttestationStatus,
    ExternalAttestation,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]


class MockAttestationProvider(AttestationProvider):
    """Mock provider for unit testing."""

    def __init__(
        self, name: str, attestations: list[ExternalAttestation], fail: bool = False
    ):
        self._name = name
        self._attestations = attestations
        self._fail = fail
        self.fetch_count = 0

    @property
    def provider_name(self) -> str:
        return self._name

    async def fetch_attestations(
        self, context: dict[str, Any]
    ) -> list[ExternalAttestation]:
        self.fetch_count += 1
        if self._fail:
            raise RuntimeError(f"Connection timeout to {self._name}")
        return list(self._attestations)


@pytest.mark.asyncio
async def test_aggregator_register_and_boot_fetch():
    """Verify registration and boot_fetch populates the cache."""
    att1 = ExternalAttestation(
        attestation_type="BLUEPRINT",
        status=AttestationStatus.VERIFIED.value,
        receipt_id="rec-bp-1",
        attested_at="2026-08-22T08:00:00Z",
        metadata={"threshold_id": "THR-FIN-006"},
    )
    att2 = ExternalAttestation(
        attestation_type="KEY",
        status=AttestationStatus.VERIFIED.value,
        receipt_id="rec-key-1",
        attested_at="2026-08-22T08:00:00Z",
    )

    p1 = MockAttestationProvider("provider-blueprint", [att1])
    p2 = MockAttestationProvider("provider-key", [att2])

    aggregator = AttestationAggregator()
    assert aggregator.provider_count == 0

    aggregator.register(p1)
    aggregator.register(p2)
    assert aggregator.provider_count == 2

    # Prior to boot_fetch, cache is empty
    assert aggregator.get_cached_attestations() == []

    await aggregator.boot_fetch()
    assert p1.fetch_count == 1
    assert p2.fetch_count == 1

    cached = aggregator.get_cached_attestations()
    assert len(cached) == 2
    assert cached[0].attestation_type == "BLUEPRINT"
    assert cached[1].attestation_type == "KEY"
    assert aggregator.last_fetch_at > 0


@pytest.mark.asyncio
async def test_aggregator_fail_open_behavior():
    """Verify failing provider does not block aggregator and records ERROR attestation."""
    att_good = ExternalAttestation(
        attestation_type="PHYSICS",
        status=AttestationStatus.VERIFIED.value,
        receipt_id="rec-phys-1",
        attested_at="2026-08-22T08:00:00Z",
    )
    p_good = MockAttestationProvider("good-provider", [att_good])
    p_bad = MockAttestationProvider("failing-provider", [], fail=True)

    aggregator = AttestationAggregator(providers=[p_good, p_bad])
    await aggregator.boot_fetch()

    cached = aggregator.get_cached_attestations()
    assert len(cached) == 2

    # Good provider result present
    assert cached[0].attestation_type == "PHYSICS"
    assert cached[0].status == AttestationStatus.VERIFIED.value

    # Failing provider result emitted as ERROR
    assert cached[1].attestation_type == "PROVIDER_ERROR:failing-provider"
    assert cached[1].status == AttestationStatus.ERROR.value
    assert "Connection timeout" in cached[1].metadata["error"]


@pytest.mark.asyncio
async def test_aggregator_poll_refreshes_cache():
    """Verify poll re-fetches attestations."""
    att = ExternalAttestation(
        attestation_type="KEY",
        status=AttestationStatus.VERIFIED.value,
        receipt_id="rec-1",
        attested_at="2026-08-22T08:00:00Z",
    )
    provider = MockAttestationProvider("prov", [att])
    aggregator = AttestationAggregator(providers=[provider])

    await aggregator.boot_fetch()
    assert provider.fetch_count == 1

    await aggregator.poll()
    assert provider.fetch_count == 2
