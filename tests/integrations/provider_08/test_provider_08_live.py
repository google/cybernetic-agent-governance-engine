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

"""Live integration tests for Verdict Systems (provider_08).

Executes live HTTP requests against the Verdict sandbox endpoint
(https://verdict.systems/api/cage) over the physical wire.

Markers:
    partner_integration: External partner integration tests
    live_external: Hits external partner APIs (requires network)
    partner: Partner adapter facet
"""

from __future__ import annotations

import os

import httpx
import pytest

from src.gateway.governance.seams.normative import (
    NormativeBaseline,
    ValidationResult,
)
from src.integrations.provider_08.adapter import (
    FINDING_CODE_ENDPOINT_ERROR,
    Provider08NormativeProvider,
)

pytestmark = [
    pytest.mark.partner_integration,
    pytest.mark.live_external,
    pytest.mark.partner,
]

_DEFAULT_LIVE_ENDPOINT = "https://verdict.systems/api/cage"


def _get_live_config() -> tuple[str, str]:
    endpoint = (
        os.environ.get("PROVIDER_08_ENDPOINT")
        or os.environ.get("CAGE_NORMATIVE_ENDPOINT")
        or _DEFAULT_LIVE_ENDPOINT
    ).rstrip("/")
    api_key = (
        os.environ.get("PROVIDER_08_API_KEY")
        or os.environ.get("CAGE_NORMATIVE_API_KEY_SECRET", "")
    ).strip()
    return endpoint, api_key


@pytest.fixture
def live_provider() -> Provider08NormativeProvider:
    endpoint, api_key = _get_live_config()
    return Provider08NormativeProvider(
        endpoint=endpoint,
        api_key=api_key,
        timeout_seconds=10.0,
    )


@pytest.mark.asyncio
async def test_live_discovery_endpoint() -> None:
    """Verify live discovery document is reachable over the wire."""
    endpoint, _ = _get_live_config()
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(endpoint)
        assert resp.status_code == 200, f"Discovery failed: {resp.status_code} {resp.text}"
        data = resp.json()
        assert data.get("provider") == "verdict.systems"
        assert "regions" in data
        assert "EU_ECB" in data["regions"]


@pytest.mark.asyncio
async def test_live_fetch_baseline_eu_ecb(
    live_provider: Provider08NormativeProvider,
) -> None:
    """Verify live baseline retrieval from Verdict sandbox without auth."""
    baseline = await live_provider.fetch_baseline("EU_ECB")
    assert isinstance(baseline, NormativeBaseline)
    assert baseline.region == "EU_ECB"
    assert baseline.error is None, f"Baseline fetch failed: {baseline.error}"
    assert baseline.is_valid
    assert baseline.etag != ""
    assert isinstance(baseline.profile, dict)


@pytest.mark.asyncio
async def test_live_fetch_baseline_unknown_region(
    live_provider: Provider08NormativeProvider,
) -> None:
    """Verify live fail-closed behavior on non-existent region."""
    baseline = await live_provider.fetch_baseline("UNKNOWN_REGION_XYZ")
    assert isinstance(baseline, NormativeBaseline)
    assert baseline.is_valid is False
    assert baseline.error is not None
    assert "404" in baseline.error


@pytest.mark.asyncio
async def test_live_validate_fria_fail_closed_without_key(
    live_provider: Provider08NormativeProvider,
) -> None:
    """Verify keyed validation endpoint fails closed (401 or 503) without valid key."""
    _, api_key = _get_live_config()
    payload = {
        "thread_id": "thread-cage-live-test-01",
        "action": "execute_transfer",
        "action_hash": "a" * 64,
        "agent_id": "agent://test",
        "policy_version": "v1.0",
    }
    if api_key:
        result = await live_provider.validate_fria(payload)
        assert isinstance(result, ValidationResult)
    else:
        # Without an API key, the live keyed endpoint must fail closed to ENDPOINT_ERROR
        result = await live_provider.validate_fria(payload)
        assert isinstance(result, ValidationResult)
        assert result.admitted is False
        assert result.findings[0]["code"] == FINDING_CODE_ENDPOINT_ERROR
