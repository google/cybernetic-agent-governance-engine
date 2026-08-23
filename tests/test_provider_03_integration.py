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

import pytest

from src.integrations.provider_03 import Provider03NormativeProvider


@pytest.mark.asyncio
async def test_provider_03_lifecycle():
    provider = Provider03NormativeProvider(
        endpoint="https://provider03.example.com", api_key="secret-key"
    )

    baseline = await provider.fetch_legal_baseline("US_FED")
    assert baseline["region"] == "US_FED"
    assert baseline["provider"] == "PROVIDER_03"
    assert "PROVIDER_03_DECISION_MANDATE_V1" in baseline["active_rules"]

    fria = await provider.validate_external_fria(
        "thread-123", {"action": "execute_trade", "amount": 5000}
    )
    assert fria["verdict"] == "APPROVED"
    assert fria["provider"] == "PROVIDER_03"
    assert fria["thread_id"] == "thread-123"

    evidence_ok = await provider.submit_evidence_chain(
        "thread-123", {"event": "trade_executed"}
    )
    assert evidence_ok is True


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
