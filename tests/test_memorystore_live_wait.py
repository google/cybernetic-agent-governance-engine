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

"""Smoke tests for Memorystore WAIT 1 100 synchronous replication (Track 6b Exit Criterion)."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scripts.smoke_test_memorystore_wait import verify_memorystore_wait

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.mark.asyncio
async def test_wait_smoke_test_dry_run() -> None:
    """Dry-run mode returns success with simulated latency fitting the budget."""
    success, acked, latency_ms, msg = await verify_memorystore_wait(
        replicas=1,
        timeout_ms=100,
        dry_run=True,
    )
    assert success is True
    assert acked == 1
    assert latency_ms <= 100.0
    assert "DRY-RUN" in msg


@pytest.mark.asyncio
async def test_wait_smoke_test_with_mocked_client() -> None:
    """Mocked Redis client acknowledging WAIT 1 within budget."""
    mock_client = AsyncMock()
    mock_client.set = AsyncMock(return_value=True)
    mock_client.execute_command = AsyncMock(return_value=1)
    mock_client.delete = AsyncMock(return_value=1)
    mock_client.aclose = AsyncMock()

    with patch("redis.asyncio.Redis", return_value=mock_client):
        success, acked, latency_ms, msg = await verify_memorystore_wait(
            host="10.0.0.10",
            port=6379,
            replicas=1,
            timeout_ms=100,
            dry_run=False,
        )

    assert success is True
    assert acked == 1
    assert "SUCCESS" in msg
    mock_client.set.assert_awaited_once()
    mock_client.execute_command.assert_awaited_once_with("WAIT", 1, 100)
    mock_client.delete.assert_awaited_once()


@pytest.mark.integration
@pytest.mark.live_external
@pytest.mark.asyncio
async def test_wait_smoke_test_live_cluster() -> None:
    """Over-the-wire live test against staging governance Memorystore instance."""
    redis_host = os.environ.get("REDIS_GOVERNANCE_HOST") or os.environ.get("REDIS_HOST")
    if not redis_host or redis_host in ("localhost", "127.0.0.1"):
        pytest.skip("REDIS_GOVERNANCE_HOST not configured for live cluster execution")

    port = int(os.environ.get("REDIS_PORT", "6379"))
    enable_tls = os.environ.get("REDIS_TLS", "").lower() in ("true", "1", "yes")
    ca_cert = os.environ.get("REDIS_CA_CERT_PATH")
    iam_auth = os.environ.get("REDIS_AUTH_MODE", "").lower() == "iam"

    success, acked, latency_ms, msg = await verify_memorystore_wait(
        host=redis_host,
        port=port,
        replicas=1,
        timeout_ms=100,
        enable_tls=enable_tls,
        ca_cert_path=ca_cert,
        iam_auth=iam_auth,
        dry_run=False,
    )

    assert success is True, f"Live WAIT smoke test failed: {msg}"
    assert acked >= 1, f"Expected >= 1 replica, got {acked}"
    assert latency_ms <= 100.0, f"WAIT latency {latency_ms:.2f} ms exceeded 100 ms budget"
