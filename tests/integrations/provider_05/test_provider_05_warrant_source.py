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

from src.gateway.governance.seams.warrant import WarrantSource
from src.gateway.governance.warrant import (
    RelianceStatus,
    Warrant,
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
