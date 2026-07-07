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


import httpx
import pytest
import respx

pytestmark = pytest.mark.unit

from src.gateway.core.policy import OPAClient


@pytest.fixture
def opa_client():
    # Force URL for testing consistency or just use what's configured
    return OPAClient()


@pytest.mark.asyncio
async def test_opa_allow(opa_client):
    # Mock the full URL configured in the client including the explain parameter
    async with respx.mock(base_url=None) as mock:
        query_url = opa_client.target_url
        mock.post(query_url).mock(
            return_value=httpx.Response(200, json={"result": "ALLOW"})
        )

        result = await opa_client.evaluate_policy({"action": "test"})
        assert result == "ALLOW"


@pytest.mark.asyncio
async def test_opa_deny(opa_client):
    async with respx.mock(base_url=None) as mock:
        query_url = opa_client.target_url
        mock.post(query_url).mock(
            return_value=httpx.Response(200, json={"result": "DENY"})
        )

        result = await opa_client.evaluate_policy({"action": "test"})
        assert result == "DENY"


@pytest.mark.asyncio
async def test_circuit_breaker(opa_client):
    # Reset CB
    opa_client.cb.state = "CLOSED"
    opa_client.cb.failures = 0

    async with respx.mock(base_url=None) as mock:
        # Simulate 5 failures
        query_url = opa_client.target_url
        mock.post(query_url).mock(return_value=httpx.Response(500))

        for _ in range(5):
            result = await opa_client.evaluate_policy({"action": "test"})
            assert result == "DENY"

        # Now CB should be OPEN
        assert opa_client.cb.state == "OPEN"
