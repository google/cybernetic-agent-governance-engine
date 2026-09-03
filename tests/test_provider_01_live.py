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

"""Live integration tests for Provider 01.

Executes live HTTP requests against the Provider 01 sandbox endpoint
when configured via environment variables or local test credentials.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from src.gateway.governance.normative_provider import (
    EvidenceSeal,
    NormativeBaseline,
    ValidationResult,
)
from src.integrations.provider_01.provider import Provider01NormativeProvider

pytestmark = [pytest.mark.eu_ecb, pytest.mark.integration, pytest.mark.live_external]


def _get_live_credentials() -> tuple[str, str]:
    """Retrieve endpoint and api key from environment variables."""
    endpoint = (
        (
            os.environ.get("PROVIDER_01_ENDPOINT")
            or os.environ.get(
                "CAGE_NORMATIVE_ENDPOINT", "https://provider-01.example.com/api/cage"
            )
        )
        .split("#")[0]
        .strip()
    )

    api_key = (
        (
            os.environ.get("PROVIDER_01_API_KEY")
            or os.environ.get("CAGE_NORMATIVE_API_KEY_SECRET", "")
        )
        .split("#")[0]
        .strip()
    )

    return endpoint, api_key


@pytest.fixture
def live_provider() -> Provider01NormativeProvider:
    endpoint, api_key = _get_live_credentials()
    if not api_key:
        pytest.skip("Provider 01 API key not configured")
    return Provider01NormativeProvider(
        endpoint=endpoint,
        api_key=api_key,
        timeout=10.0,
    )


@pytest.mark.asyncio
async def test_live_health_and_baseline_fetch(
    live_provider: Provider01NormativeProvider,
) -> None:
    """Verify live legal-baseline endpoint for EU_ECB."""
    baseline = await live_provider.fetch_baseline("EU_ECB")
    assert isinstance(baseline, NormativeBaseline)
    assert baseline.region == "EU_ECB"
    assert baseline.error is None
    assert baseline.etag is not None
    assert "CTRL_FRIA_006" in baseline.profile


@pytest.mark.asyncio
async def test_live_validate_fria(live_provider: Provider01NormativeProvider) -> None:
    """Verify live FRIA validation endpoint."""
    payload: dict[str, Any] = {
        "thread_id": "thread-cage-live-test-01",
        "action": "payment.wire.execute",
        "region": "EU_ECB",
        "context": {"risk_tier": "standard"},
    }
    result = await live_provider.validate_fria(payload)
    assert isinstance(result, ValidationResult)
    assert result.admitted is True
    assert result.error is None


@pytest.mark.asyncio
async def test_live_submit_evidence(
    live_provider: Provider01NormativeProvider,
) -> None:
    """Verify live evidence-chain logging endpoint."""
    thread_id = "thread-cage-live-test-01"
    evidence_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    seal = await live_provider.submit_evidence(thread_id, evidence_hash)
    assert isinstance(seal, EvidenceSeal)
    assert seal.thread_id == thread_id
    assert seal.error is None
    assert len(seal.seal_hash) == 64
