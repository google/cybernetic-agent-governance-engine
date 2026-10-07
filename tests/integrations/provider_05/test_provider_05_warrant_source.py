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
``WarrantSource`` seam conformance for ``Provider05WarrantSource``.

Checks the seam contract (protocol shape, fail-closed ``None`` for MISSING,
warrants returned exactly as issued) and replays the VEIP v0.1 vectors through
seed -> fetch -> kernel verifier, so the pinned published digests survive the
source boundary byte-for-byte.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import pytest

from src.gateway.governance.seams.ground_truth import FaultMode
from src.gateway.governance.seams.warrant import WarrantSource
from src.gateway.governance.warrant import (
    RelianceStatus,
    Warrant,
    WarrantCache,
    WarrantClock,
    WarrantFreshness,
    WarrantStandingVerifier,
)
from src.integrations.provider_05 import Provider05WarrantSource
from tests.integrations.provider_05.test_provider_05_veip_vectors import (
    SHARED_CONTEXT,
    SHARED_WARRANT,
    VEIP_ACTIVE_DIGEST,
    VEIP_REVOKED_DIGEST,
    VEIP_V01_VECTORS,
)

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.partner]

NORM_ID = SHARED_WARRANT["norm_id"]


def _verify(warrant: Warrant | None, context: dict[str, Any]):
    ctx = dict(context)
    now = datetime.fromisoformat(ctx.pop("evaluation_timestamp").replace("Z", "+00:00"))
    return WarrantStandingVerifier.verify_standing(warrant, context=ctx, now=now)


def test_satisfies_warrant_source_protocol() -> None:
    source = Provider05WarrantSource()
    assert isinstance(source, WarrantSource)
    assert source.provider_name == "provider_05_warrant"


@pytest.mark.asyncio
async def test_unseeded_norm_is_missing() -> None:
    source = Provider05WarrantSource()
    warrant = await source.fetch(NORM_ID)
    assert warrant is None
    result = _verify(warrant, SHARED_CONTEXT)
    assert result.reliance_status == RelianceStatus.INELIGIBLE_MISSING


@pytest.mark.asyncio
async def test_configured_endpoint_still_fails_closed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The HTTP path is unimplemented: an endpoint never yields a warrant."""
    source = Provider05WarrantSource(endpoint="https://veip.invalid/")
    with caplog.at_level(logging.WARNING):
        assert await source.fetch(NORM_ID) is None
    assert "unimplemented" in caplog.text


@pytest.mark.asyncio
async def test_endpoint_env_var_does_not_enable_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PROVIDER_05_ATTESTATION_ENDPOINT", "https://veip.invalid")
    assert await Provider05WarrantSource().fetch(NORM_ID) is None


@pytest.mark.asyncio
async def test_fetch_returns_warrant_exactly_as_issued() -> None:
    issued = Warrant(**SHARED_WARRANT)
    source = Provider05WarrantSource()
    source.seed(issued)
    fetched = await source.fetch(NORM_ID)
    assert fetched is issued
    assert fetched.digest == VEIP_ACTIVE_DIGEST
    assert await source.fetch("some.other.norm") is None


@pytest.mark.asyncio
async def test_reseed_replaces_current_warrant() -> None:
    """Issuer lifecycle: a revocation supersedes the active warrant."""
    source = Provider05WarrantSource()
    source.seed(Warrant(**SHARED_WARRANT))
    source.seed(
        Warrant(
            **{
                **SHARED_WARRANT,
                "status": "REVOKED",
                "revocation_ref": "Emergency Risk Notice #912",
                "digest": VEIP_REVOKED_DIGEST,
            }
        )
    )
    result = _verify(await source.fetch(NORM_ID), SHARED_CONTEXT)
    assert result.reliance_status == RelianceStatus.INELIGIBLE_REVOKED
    assert result.warrant_digest == VEIP_REVOKED_DIGEST


@pytest.mark.asyncio
@pytest.mark.parametrize(("warrant", "context", "expected"), VEIP_V01_VECTORS)
async def test_veip_vectors_through_source(
    warrant: dict[str, Any], context: dict[str, Any], expected: RelianceStatus
) -> None:
    source = Provider05WarrantSource()
    source.seed(Warrant(**warrant))
    result = _verify(await source.fetch(warrant["norm_id"]), context)
    assert result.reliance_status == expected, result.reason
    assert result.warrant_digest == warrant["digest"]


# --- Fault injection (every fail-closed path) ----------------------------------


def _seeded() -> Provider05WarrantSource:
    source = Provider05WarrantSource()
    source.seed(Warrant(**SHARED_WARRANT))
    return source


@pytest.mark.parametrize(
    ("fault", "exc"),
    [(FaultMode.TIMEOUT, TimeoutError), (FaultMode.CONNECTION_ERROR, ConnectionError)],
    ids=str,
)
async def test_transport_faults_raise(fault: FaultMode, exc: type[Exception]) -> None:
    source = _seeded()
    source.inject_fault(fault)
    assert source.fault_mode is fault
    with pytest.raises(exc):
        await source.fetch(NORM_ID)


async def test_malformed_payload_is_not_a_warrant() -> None:
    source = _seeded()
    source.inject_fault("malformed_payload")
    payload = await source.fetch(NORM_ID)
    assert isinstance(payload, dict) and not isinstance(payload, Warrant)
    assert payload["digest"] == VEIP_ACTIVE_DIGEST


async def test_unverified_source_rewrites_fields_but_keeps_the_declared_digest() -> (
    None
):
    source = _seeded()
    source.inject_fault(FaultMode.UNVERIFIED_SOURCE)
    warrant = await source.fetch(NORM_ID)
    assert isinstance(warrant, Warrant)
    assert warrant.digest == VEIP_ACTIVE_DIGEST
    assert warrant.compute_digest() != VEIP_ACTIVE_DIGEST
    result = _verify(warrant, SHARED_CONTEXT)
    assert result.reliance_status == RelianceStatus.INELIGIBLE_UNRESOLVED


@pytest.mark.parametrize(
    "fault",
    [
        FaultMode.TIMEOUT,
        FaultMode.CONNECTION_ERROR,
        FaultMode.MALFORMED_PAYLOAD,
    ],
    ids=str,
)
async def test_cache_treats_every_transport_fault_as_unresolved_then_stale(
    fault: FaultMode,
) -> None:
    """Through the kernel cache: no state is trusted, none is extended."""
    now = [0.0]
    source = _seeded()
    cache = WarrantCache(
        source,
        monotonic=WarrantClock(monotonic=lambda: now[0]).monotonic,
    )
    source.inject_fault(fault)
    cold = await cache.observe(NORM_ID)
    assert cold.freshness is WarrantFreshness.UNRESOLVED and cold.warrant is None

    source.clear_fault()
    assert (await cache.observe(NORM_ID)).fresh
    source.inject_fault(fault)
    now[0] += 60.001
    stale = await cache.observe(NORM_ID)
    assert stale.freshness is WarrantFreshness.STALE
    assert stale.warrant is not None and stale.warrant.digest == VEIP_ACTIVE_DIGEST


@pytest.mark.parametrize(
    "fault",
    sorted(
        {
            FaultMode.NAN_VALUE,
            FaultMode.NEGATIVE_VALUE,
            FaultMode.STALE_TIMESTAMP,
            FaultMode.SETTLEMENT_STALL,
        }
    ),
    ids=str,
)
def test_faults_without_a_warrant_meaning_are_refused(fault: FaultMode) -> None:
    source = _seeded()
    with pytest.raises(ValueError, match="no warrant-source meaning"):
        source.inject_fault(fault)
    assert source.fault_mode is FaultMode.NONE


def test_unknown_fault_name_is_refused() -> None:
    with pytest.raises(ValueError):
        Provider05WarrantSource().inject_fault("bit_flip")


async def test_clear_fault_restores_the_seeded_warrant() -> None:
    source = _seeded()
    source.inject_fault(FaultMode.CONNECTION_ERROR)
    source.clear_fault()
    warrant = await source.fetch(NORM_ID)
    assert isinstance(warrant, Warrant) and warrant.digest == VEIP_ACTIVE_DIGEST
