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
from src.gateway.governance.seams.attestation import (
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
        provider_name="provider-blueprint",
        metadata={"threshold_id": "THR-FIN-006"},
    )
    att2 = ExternalAttestation(
        attestation_type="KEY",
        status=AttestationStatus.VERIFIED.value,
        receipt_id="rec-key-1",
        attested_at="2026-08-22T08:00:00Z",
        provider_name="provider-key",
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
    assert cached[0].provider_name == "provider-blueprint"
    assert cached[1].attestation_type == "KEY"
    assert cached[1].provider_name == "provider-key"
    assert aggregator.last_fetch_at > 0
    assert aggregator.last_fetch_succeeded is True


@pytest.mark.asyncio
async def test_aggregator_fail_open_behavior():
    """Verify failing provider does not block aggregator and records ERROR attestation."""
    att_good = ExternalAttestation(
        attestation_type="PHYSICS",
        status=AttestationStatus.VERIFIED.value,
        receipt_id="rec-phys-1",
        attested_at="2026-08-22T08:00:00Z",
        provider_name="good-provider",
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
    assert cached[0].provider_name == "good-provider"

    # Failing provider result emitted as ERROR with first-class provider_name
    # (defect a fix — no longer PROVIDER_ERROR:failing-provider)
    assert cached[1].attestation_type == "ERROR"
    assert cached[1].status == AttestationStatus.ERROR.value
    assert cached[1].provider_name == "failing-provider"
    assert "Connection timeout" in cached[1].metadata["error"]


@pytest.mark.asyncio
async def test_aggregator_poll_refreshes_cache():
    """Verify poll re-fetches attestations."""
    att = ExternalAttestation(
        attestation_type="KEY",
        status=AttestationStatus.VERIFIED.value,
        receipt_id="rec-1",
        attested_at="2026-08-22T08:00:00Z",
        provider_name="prov",
    )
    provider = MockAttestationProvider("prov", [att])
    aggregator = AttestationAggregator(providers=[provider])

    await aggregator.boot_fetch()
    assert provider.fetch_count == 1

    await aggregator.poll()
    assert provider.fetch_count == 2


def test_aggregator_register_validates_protocol():
    """Verify register() enforces AttestationProvider protocol with isinstance check."""
    att = ExternalAttestation(
        attestation_type="TEST",
        status=AttestationStatus.VERIFIED.value,
        receipt_id="rec-1",
        attested_at="2026-09-09T17:00:00Z",
        provider_name="test-provider",
    )
    conforming_provider = MockAttestationProvider("test-provider", [att])
    aggregator = AttestationAggregator()

    # Conforming provider succeeds
    aggregator.register(conforming_provider)
    assert aggregator.provider_count == 1


def test_aggregator_register_rejects_non_conforming_object():
    """Verify register() raises TypeError for non-conforming objects."""
    aggregator = AttestationAggregator()

    # Non-conforming object (plain dict) should raise TypeError
    with pytest.raises(
        TypeError,
        match=r"Provider must implement AttestationProvider protocol, got <class 'dict'>",
    ):
        aggregator.register({"provider_name": "fake"})  # type: ignore[arg-type]


def test_aggregator_register_no_partial_mutation_on_rejection():
    """Verify rejected registration leaves provider list unchanged."""
    att = ExternalAttestation(
        attestation_type="TEST",
        status=AttestationStatus.VERIFIED.value,
        receipt_id="rec-1",
        attested_at="2026-09-09T17:00:00Z",
        provider_name="valid",
    )
    valid_provider = MockAttestationProvider("valid", [att])
    aggregator = AttestationAggregator()

    # Register valid provider first
    aggregator.register(valid_provider)
    assert aggregator.provider_count == 1

    # Attempt to register invalid object
    with pytest.raises(TypeError, match="AttestationProvider protocol"):
        aggregator.register("not-a-provider")  # type: ignore[arg-type]

    # Provider list should remain unchanged (no partial mutation)
    assert aggregator.provider_count == 1
    assert aggregator._providers[0] is valid_provider


# ---------------------------------------------------------------------------
# Phase 5b (C3) — Attestation Failure Attributability Tests
# ---------------------------------------------------------------------------


class RaisingNameProvider(AttestationProvider):
    """Mock provider whose provider_name property raises (defect b test)."""

    @property
    def provider_name(self) -> str:
        raise RuntimeError("Database connection error reading provider metadata")

    async def fetch_attestations(
        self, context: dict[str, Any]
    ) -> list[ExternalAttestation]:
        # Also fail the fetch to produce an ERROR entry
        raise RuntimeError("Fetch also failed")


@pytest.mark.asyncio
async def test_c3_req1_raising_provider_name_does_not_abort_loop():
    """C3 Requirement 1: A provider whose provider_name raises does not prevent subsequent providers from being fetched.

    Defect (b): provider.provider_name was evaluated INSIDE the except block,
    so a provider whose property itself raises would escape the handler and
    abort the whole fetch loop, dropping every subsequent provider.

    Fix: Capture provider_name BEFORE the try block. If provider_name itself
    raises, handle it and continue with a placeholder identity.
    """
    att_good = ExternalAttestation(
        attestation_type="SAFE",
        status=AttestationStatus.VERIFIED.value,
        receipt_id="rec-safe-1",
        attested_at="2026-09-09T19:00:00Z",
        provider_name="safe-provider",
    )
    p_safe = MockAttestationProvider("safe-provider", [att_good])
    p_raising = RaisingNameProvider()

    # Order matters: raising provider first, safe provider second
    aggregator = AttestationAggregator(providers=[p_raising, p_safe])
    await aggregator.boot_fetch()

    cached = aggregator.get_cached_attestations()
    # Should have 2 entries: 1 ERROR from raising provider, 1 VERIFIED from safe provider
    assert len(cached) == 2

    # First entry: ERROR from raising provider (with placeholder name)
    assert cached[0].attestation_type == "ERROR"
    assert cached[0].status == AttestationStatus.ERROR.value
    assert "<unknown-provider-" in cached[0].provider_name
    assert "Fetch also failed" in cached[0].metadata["error"]

    # Second entry: VERIFIED from safe provider (proves loop did not abort)
    assert cached[1].attestation_type == "SAFE"
    assert cached[1].status == AttestationStatus.VERIFIED.value
    assert cached[1].provider_name == "safe-provider"


@pytest.mark.asyncio
async def test_c3_req2_total_failure_retains_prior_cache():
    """C3 Requirement 2: Total failure retains prior cache and does not advance _last_fetch_at.

    Defect (c): self._cache = all_attestations replaced the cache wholesale,
    so a total-failure poll silently discarded the previous good attestation set.

    Defect (d): _last_fetch_at was set even when every provider failed, so
    staleness monitors read a healthy timestamp over a fully-failed fetch.

    Fix: On total failure (success_count == 0), retain prior cache and leave
    _last_fetch_at unchanged.
    """
    att_initial = ExternalAttestation(
        attestation_type="INITIAL",
        status=AttestationStatus.VERIFIED.value,
        receipt_id="rec-initial-1",
        attested_at="2026-09-09T18:00:00Z",
        provider_name="initial-provider",
    )
    p_initial = MockAttestationProvider("initial-provider", [att_initial])

    # First fetch: establish a good cache
    aggregator = AttestationAggregator(providers=[p_initial])
    await aggregator.boot_fetch()
    assert len(aggregator.get_cached_attestations()) == 1
    assert aggregator.last_fetch_succeeded is True
    first_timestamp = aggregator.last_fetch_at

    # Replace provider with a failing one
    p_fail = MockAttestationProvider("failing-provider", [], fail=True)
    aggregator._providers = [p_fail]

    # Second fetch: total failure
    await aggregator.poll()

    # Cache should RETAIN the prior good attestation, not replace it with []
    cached = aggregator.get_cached_attestations()
    assert len(cached) == 1
    assert cached[0].attestation_type == "INITIAL"
    assert cached[0].receipt_id == "rec-initial-1"

    # Timestamp should NOT advance
    assert aggregator.last_fetch_at == first_timestamp

    # Staleness signal should be False
    assert aggregator.last_fetch_succeeded is False


@pytest.mark.asyncio
async def test_c3_req3_total_failure_surfaces_staleness_signal():
    """C3 Requirement 3: Total failure surfaces explicit staleness signal.

    Defect (d): _last_fetch_at is set even when every provider failed, so
    staleness monitors read a healthy timestamp over a fully-failed fetch.

    Fix: Introduce _last_fetch_succeeded boolean. On total failure, set it to
    False. Monitors can check this to distinguish "poll ran but all failed"
    from "poll succeeded".
    """
    p_fail = MockAttestationProvider("failing-provider", [], fail=True)
    aggregator = AttestationAggregator(providers=[p_fail])

    # Initial state
    assert aggregator.last_fetch_succeeded is False
    assert aggregator.last_fetch_at == 0.0

    # First fetch: total failure
    await aggregator.boot_fetch()

    # Staleness signal should be False (total failure)
    assert aggregator.last_fetch_succeeded is False
    # Timestamp should still be 0.0 (not advanced)
    assert aggregator.last_fetch_at == 0.0

    # Cache should contain 1 ERROR entry for audit trail (no prior good state to retain)
    cached = aggregator.get_cached_attestations()
    assert len(cached) == 1
    assert cached[0].attestation_type == "ERROR"
    assert cached[0].provider_name == "failing-provider"


@pytest.mark.asyncio
async def test_c3_req4_partial_failure_updates_cache_normally():
    """C3 Requirement 4: Partial failure updates cache and timestamp normally.

    A partial failure (some providers succeed, some fail) should update the
    cache with both the successful attestations and ERROR entries for the
    failed providers. Timestamp should advance normally.
    """
    att_good = ExternalAttestation(
        attestation_type="GOOD",
        status=AttestationStatus.VERIFIED.value,
        receipt_id="rec-good-1",
        attested_at="2026-09-09T19:00:00Z",
        provider_name="good-provider",
    )
    p_good = MockAttestationProvider("good-provider", [att_good])
    p_fail = MockAttestationProvider("failing-provider", [], fail=True)

    aggregator = AttestationAggregator(providers=[p_good, p_fail])
    await aggregator.boot_fetch()

    # Cache should contain both: 1 VERIFIED + 1 ERROR
    cached = aggregator.get_cached_attestations()
    assert len(cached) == 2

    # First entry: VERIFIED from good provider
    assert cached[0].attestation_type == "GOOD"
    assert cached[0].status == AttestationStatus.VERIFIED.value
    assert cached[0].provider_name == "good-provider"

    # Second entry: ERROR from failing provider
    assert cached[1].attestation_type == "ERROR"
    assert cached[1].status == AttestationStatus.ERROR.value
    assert cached[1].provider_name == "failing-provider"

    # Timestamp should advance (partial success)
    assert aggregator.last_fetch_at > 0
    # Staleness signal should be True (at least one success)
    assert aggregator.last_fetch_succeeded is True


@pytest.mark.asyncio
async def test_c3_req5_error_entries_discoverable_via_provider_name():
    """C3 Requirement 5: Error entries discoverable via provider_name without string-prefix matching.

    Defect (a): attestation_type was overloaded as PROVIDER_ERROR:{name}, so
    error entries were only discoverable by string-prefix matching.

    Fix: Use first-class provider_name field. Error entries have
    attestation_type="ERROR" and provider_name=<actual-name>.
    """
    p_fail1 = MockAttestationProvider("provider-alpha", [], fail=True)
    p_fail2 = MockAttestationProvider("provider-beta", [], fail=True)

    aggregator = AttestationAggregator(providers=[p_fail1, p_fail2])
    await aggregator.boot_fetch()

    cached = aggregator.get_cached_attestations()
    assert len(cached) == 2

    # Both should be ERROR entries with canonical type
    assert all(a.attestation_type == "ERROR" for a in cached)
    assert all(a.status == AttestationStatus.ERROR.value for a in cached)

    # Discoverable by direct provider_name lookup (no string matching)
    error_by_provider = {a.provider_name: a for a in cached}
    assert "provider-alpha" in error_by_provider
    assert "provider-beta" in error_by_provider

    # Verify no PROVIDER_ERROR:{name} pattern
    assert not any("PROVIDER_ERROR:" in a.attestation_type for a in cached)
