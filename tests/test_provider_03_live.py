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

"""Live integration tests for Provider 03 (normative baseline).

Executes live HTTP requests against the Provider 03 sandbox endpoint
when configured via environment variables.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from src.gateway.governance.seams.normative import NormativeBaseline
from src.integrations.provider_03.provider import Provider03NormativeProvider

pytestmark = [
    pytest.mark.partner_integration,
    pytest.mark.live_external,
    pytest.mark.partner,
]


def _get_live_credentials() -> tuple[str, str]:
    """Retrieve endpoint and API key from environment variables."""
    endpoint = (
        os.environ.get("PROVIDER_03_ENDPOINT", "")
        .split("#")[0]
        .strip()
    )

    api_key = (
        os.environ.get("PROVIDER_03_API_KEY", "")
        .split("#")[0]
        .strip()
    )

    return endpoint, api_key


@pytest.fixture
def live_provider() -> Provider03NormativeProvider:
    """Create a live Provider 03 provider instance."""
    endpoint, api_key = _get_live_credentials()
    
    if not endpoint:
        pytest.skip("PROVIDER_03_ENDPOINT not configured")
    
    return Provider03NormativeProvider(
        endpoint=endpoint,
        api_key=api_key,
        timeout=10.0,
    )


@pytest.mark.asyncio
async def test_live_fetch_baseline(
    live_provider: Provider03NormativeProvider,
) -> None:
    """Verify live baseline retrieval for a test region."""
    # Use a test region or default to EU_ECB
    test_region = os.environ.get("PROVIDER_03_TEST_REGION", "EU_ECB")
    
    baseline = await live_provider.fetch_baseline(test_region)
    
    # Assert baseline structure
    assert isinstance(baseline, NormativeBaseline)
    assert baseline.region == test_region
    assert baseline.error is None, f"Baseline fetch failed: {baseline.error}"
    assert baseline.profile, "Profile should not be empty"
    
    # Provider 03 should return an ETag for cache validation
    if baseline.etag:
        assert isinstance(baseline.etag, str), "ETag should be a string"


@pytest.mark.asyncio
async def test_live_validate_fria(
    live_provider: Provider03NormativeProvider,
) -> None:
    """Verify live FRIA validation endpoint."""
    payload: dict[str, Any] = {
        "thread_id": "thread-cage-live-provider03-001",
        "action": "test.action.validate",
        "region": "EU_ECB",
        "action_context": {
            "risk_tier": "standard",
            "test": True,
        },
    }
    
    result = await live_provider.validate_fria(payload)
    
    # Assert validation result structure
    assert result.error is None, f"Validation failed: {result.error}"
    
    # Result should have admitted flag and findings
    assert isinstance(result.admitted, bool)
    assert isinstance(result.findings, list)
    
    # If approved, admitted should be True
    if result.admitted:
        assert not any(
            f.get("severity") == "blocked" for f in result.findings
        ), "Approved result should not have blocking findings"


@pytest.mark.asyncio
async def test_live_submit_evidence(
    live_provider: Provider03NormativeProvider,
) -> None:
    """Verify live evidence submission endpoint."""
    thread_id = "thread-cage-live-provider03-002"
    evidence_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    
    seal = await live_provider.submit_evidence(thread_id, evidence_hash)
    
    # Assert evidence seal structure
    assert seal.thread_id == thread_id
    assert seal.error is None, f"Evidence submission failed: {seal.error}"
    assert seal.seal_hash, "Seal hash should be present"
    assert len(seal.seal_hash) == 64, "Seal hash should be 64-char hex"


@pytest.mark.asyncio
async def test_live_baseline_cache_staleness(
    live_provider: Provider03NormativeProvider,
) -> None:
    """Verify baseline cache staleness detection via ETag.
    
    This test fetches the baseline twice and verifies that the ETag
    mechanism works correctly for cache validation.
    """
    test_region = os.environ.get("PROVIDER_03_TEST_REGION", "EU_ECB")
    
    # First fetch
    baseline1 = await live_provider.fetch_baseline(test_region)
    assert baseline1.error is None, f"First fetch failed: {baseline1.error}"
    etag1 = baseline1.etag
    
    # Second fetch (should potentially use cached version)
    baseline2 = await live_provider.fetch_baseline(test_region)
    assert baseline2.error is None, f"Second fetch failed: {baseline2.error}"
    etag2 = baseline2.etag
    
    # ETags should match if content hasn't changed
    if etag1 and etag2:
        assert etag1 == etag2, "ETags should match for unchanged baseline"
