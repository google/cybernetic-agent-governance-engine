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

"""Unit tests for Provider01NormativeProvider adapter."""

from __future__ import annotations

import httpx
import pytest
import respx

from src.integrations.provider_01.provider import Provider01NormativeProvider

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def provider() -> Provider01NormativeProvider:
    return Provider01NormativeProvider(
        endpoint="https://provider01.example.com",
        api_key="test-api-key",
        timeout=2.0,
    )


@pytest.mark.asyncio
@respx.mock
async def test_fetch_baseline_success(provider: Provider01NormativeProvider) -> None:
    respx.get("https://provider01.example.com/legal-baseline/US_FED").mock(
        return_value=httpx.Response(
            200,
            json={"profile": {"rule": "allow"}},
            headers={"ETag": "etag-123"},
        )
    )
    baseline = await provider.fetch_baseline("US_FED")
    assert baseline.region == "US_FED"
    assert baseline.profile == {"rule": "allow"}
    assert baseline.etag == "etag-123"
    assert baseline.error is None


@pytest.mark.asyncio
@respx.mock
async def test_fetch_baseline_error(provider: Provider01NormativeProvider) -> None:
    respx.get("https://provider01.example.com/legal-baseline/US_FED").mock(
        return_value=httpx.Response(500)
    )
    baseline = await provider.fetch_baseline("US_FED")
    assert baseline.region == "US_FED"
    assert baseline.error is not None


@pytest.mark.asyncio
@respx.mock
async def test_validate_fria_success(provider: Provider01NormativeProvider) -> None:
    respx.post("https://provider01.example.com/validate/fria").mock(
        return_value=httpx.Response(
            200,
            json={"admitted": True, "findings": []},
        )
    )
    result = await provider.validate_fria({"action": "trade"})
    assert result.admitted is True
    assert result.findings == []


@pytest.mark.asyncio
@respx.mock
async def test_validate_fria_error(provider: Provider01NormativeProvider) -> None:
    respx.post("https://provider01.example.com/validate/fria").mock(
        return_value=httpx.Response(502)
    )
    result = await provider.validate_fria({"action": "trade"})
    assert result.admitted is False
    assert result.error is not None


@pytest.mark.asyncio
@respx.mock
async def test_submit_evidence_success(provider: Provider01NormativeProvider) -> None:
    respx.get("https://provider01.example.com/evidence-chain/thread-1").mock(
        return_value=httpx.Response(
            200,
            json={"seal_hash": "seal-abc-123"},
        )
    )
    seal = await provider.submit_evidence("thread-1", "evidence-hash-1")
    assert seal.thread_id == "thread-1"
    assert seal.seal_hash == "seal-abc-123"
    assert seal.error is None


@pytest.mark.asyncio
@respx.mock
async def test_submit_evidence_error(provider: Provider01NormativeProvider) -> None:
    respx.get("https://provider01.example.com/evidence-chain/thread-1").mock(
        return_value=httpx.Response(500)
    )
    seal = await provider.submit_evidence("thread-1", "evidence-hash-1")
    assert seal.thread_id == "thread-1"
    assert seal.error is not None
