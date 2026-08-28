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
Unit tests for Provider03NormativeProvider adapter (CAGE-REM-006).
"""

from __future__ import annotations

import httpx
import pytest
import respx

from src.integrations.provider_03 import Provider03NormativeProvider


@pytest.mark.asyncio
@respx.mock
async def test_provider_03_lifecycle():
    provider = Provider03NormativeProvider(
        endpoint="https://provider03.example.com", api_key="secret-key"
    )

    respx.get("https://provider03.example.com/baseline/US_FED").mock(
        return_value=httpx.Response(
            200,
            json={
                "profile": {
                    "rule": "allow",
                    "active_rules": ["PROVIDER_03_DECISION_MANDATE_V1"],
                },
                "provider": "PROVIDER_03",
            },
            headers={"ETag": "etag-3"},
        )
    )
    baseline = await provider.fetch_baseline("US_FED")
    assert baseline.region == "US_FED"
    assert baseline.profile == {
        "rule": "allow",
        "active_rules": ["PROVIDER_03_DECISION_MANDATE_V1"],
    }
    assert baseline.etag == "etag-3"

    respx.post("https://provider03.example.com/validate").mock(
        return_value=httpx.Response(
            200,
            json={"verdict": "APPROVED", "findings": []},
        )
    )
    fria = await provider.validate_fria(
        {"action": "execute_trade", "amount": 5000, "thread_id": "thread-123"}
    )
    assert fria.admitted is True
    assert fria.findings == []

    respx.post("https://provider03.example.com/evidence/thread-123").mock(
        return_value=httpx.Response(
            200,
            json={"seal_hash": "sha256-hash-xyz"},
        )
    )
    seal = await provider.submit_evidence("thread-123", "sha256-evidence-hash")
    assert seal.thread_id == "thread-123"
    assert seal.seal_hash == "sha256-hash-xyz"


def test_provider_03_bind_receipt_ingestion():
    provider = Provider03NormativeProvider()
    receipt = {
        "receipt_id": "rcpt-9988",
        "action": "execute_trade",
        "symbol": "AAPL",
        "standing": {"allowed": True},
    }
    digest = provider.ingest_bind_receipt(receipt)
    assert isinstance(digest, str)
    assert len(digest) == 64


pytestmark = [pytest.mark.unit, pytest.mark.local]
