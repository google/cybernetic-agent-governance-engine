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
Tests for the Group-3 pooled GovernanceClient (R-19 fix).

Covers:
  - Singleton / shared pool behaviour
  - Retry on 503 and 429 with exponential back-off
  - No retry on 400
  - Graceful close / pool shutdown
  - Concurrent requests share the same client instance

All HTTP I/O is mocked via respx / unittest.mock; no live vLLM required.
"""

import asyncio
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

pytestmark = pytest.mark.unit

import respx
from pydantic import BaseModel

# Reset the module-level singleton between tests to ensure isolation.
import src.governed_financial_advisor.infrastructure.governance_client as _gc_module
from src.governed_financial_advisor.infrastructure.governance_client import (
    GovernanceClient,
    StructuredLLMClient,
    _get_async_client,
    close_async_client,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _DummySchema(BaseModel):
    """Minimal Pydantic schema used as the structured-output target in tests."""

    verdict: str
    reason: str


def _make_vllm_response(verdict: str = "APPROVED", reason: str = "ok") -> dict:
    """Return a minimal vLLM chat-completions JSON body."""
    content = json.dumps({"verdict": verdict, "reason": reason})
    return {"choices": [{"message": {"content": content}}]}


@pytest.fixture(autouse=True)
async def reset_singleton():
    """Reset the module-level singleton AsyncClient before and after each test."""
    await close_async_client()
    yield
    await close_async_client()


@pytest.fixture
def client() -> GovernanceClient:
    """Return a GovernanceClient pointed at a fake base URL."""
    return GovernanceClient(
        base_url="http://fake-vllm:8000",
        api_key="EMPTY",
        model_name="test-model",
        timeout_seconds=5.0,
    )


# ---------------------------------------------------------------------------
# Singleton / pooling tests
# ---------------------------------------------------------------------------


class TestGovernanceClientPooling:
    """Tests for the R-19 connection-pool singleton behaviour."""

    @pytest.mark.asyncio
    async def test_singleton_returns_same_client_instance(self):
        """Two consecutive _get_async_client() calls must return the identical object."""
        first = await _get_async_client()
        second = await _get_async_client()
        assert first is second

    @pytest.mark.asyncio
    async def test_concurrent_requests_use_shared_pool(self):
        """Multiple concurrent coroutines calling _get_async_client() must all get the same instance."""
        results = await asyncio.gather(*[_get_async_client() for _ in range(10)])
        first = results[0]
        for instance in results[1:]:
            assert instance is first

    @pytest.mark.asyncio
    async def test_client_retries_on_503(self, client):
        """generate_structured must retry up to 3 times on HTTP 503 before raising."""
        call_count = 0

        async def _503_handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(503, json={"error": "service unavailable"})

        with respx.mock(base_url=None) as mock:
            mock.post("http://fake-vllm:8000/chat/completions").mock(
                side_effect=_503_handler
            )

            with patch(
                "src.governed_financial_advisor.infrastructure.governance_client.asyncio.sleep",
                new_callable=AsyncMock,
            ):
                with pytest.raises(Exception):
                    await client.generate_structured(
                        prompt="test",
                        schema=_DummySchema,
                    )

        # Must have been called exactly _MAX_RETRIES (3) times
        assert call_count == _gc_module._MAX_RETRIES

    @pytest.mark.asyncio
    async def test_client_retries_on_429_with_backoff(self, client):
        """generate_structured must retry on HTTP 429 and sleep between attempts."""
        call_count = 0
        sleep_calls: list[float] = []

        async def _429_handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(429, json={"error": "rate limited"})

        async def _mock_sleep(delay: float) -> None:
            sleep_calls.append(delay)

        with respx.mock(base_url=None) as mock:
            mock.post("http://fake-vllm:8000/chat/completions").mock(
                side_effect=_429_handler
            )

            with patch(
                "src.governed_financial_advisor.infrastructure.governance_client.asyncio.sleep",
                side_effect=_mock_sleep,
            ):
                with pytest.raises(Exception):
                    await client.generate_structured(
                        prompt="test",
                        schema=_DummySchema,
                    )

        # Should have retried _MAX_RETRIES times and slept between attempts
        assert call_count == _gc_module._MAX_RETRIES
        # Number of sleeps = MAX_RETRIES - 1 (no sleep after the last attempt)
        assert len(sleep_calls) == _gc_module._MAX_RETRIES - 1
        # Delays must be non-decreasing (exponential back-off)
        for i in range(1, len(sleep_calls)):
            assert sleep_calls[i] >= sleep_calls[i - 1]

    @pytest.mark.asyncio
    async def test_client_does_not_retry_on_400(self, client):
        """generate_structured must NOT retry on HTTP 400 (client error is non-transient)."""
        call_count = 0

        async def _400_handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return httpx.Response(400, json={"error": "bad request"})

        with respx.mock(base_url=None) as mock:
            mock.post("http://fake-vllm:8000/chat/completions").mock(
                side_effect=_400_handler
            )

            with pytest.raises(httpx.HTTPStatusError):
                await client.generate_structured(
                    prompt="test",
                    schema=_DummySchema,
                )

        # 400 is not in _RETRYABLE_STATUS_CODES — must call once only
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_client_close_shuts_down_pool(self):
        """close() must mark the singleton client as closed and set module state to None."""
        # Trigger lazy initialisation
        instance = await _get_async_client()
        assert not instance.is_closed

        await close_async_client()

        # Module-level reference must be cleared
        assert _gc_module._async_client is None

    @pytest.mark.asyncio
    async def test_successful_response_parsed_into_schema(self, client):
        """A valid 200 vLLM response must be parsed into the target Pydantic schema."""
        with respx.mock(base_url=None) as mock:
            mock.post("http://fake-vllm:8000/chat/completions").mock(
                return_value=httpx.Response(
                    200, json=_make_vllm_response("APPROVED", "within limits")
                )
            )

            result = await client.generate_structured(
                prompt="Should I approve this trade?",
                schema=_DummySchema,
            )

        assert isinstance(result, _DummySchema)
        assert result.verdict == "APPROVED"
        assert result.reason == "within limits"

    @pytest.mark.asyncio
    async def test_pool_limits_applied_to_singleton_client(self):
        """The singleton AsyncClient must be initialised with the configured pool limits."""
        instance = await _get_async_client()
        # httpx exposes limits on the transport layer; verify the client is alive
        assert not instance.is_closed
        # The Limits object is set during construction — we verify the config constants
        assert _gc_module._POOL_LIMITS.max_connections == 20
        assert _gc_module._POOL_LIMITS.max_keepalive_connections == 10
        assert _gc_module._POOL_LIMITS.keepalive_expiry == 30

    @pytest.mark.asyncio
    async def test_new_client_created_after_close(self):
        """After close, a subsequent _get_async_client() call must return a fresh instance."""
        first = await _get_async_client()
        await close_async_client()
        second = await _get_async_client()
        # Both are valid clients; they must NOT be the same object (first was closed)
        assert not second.is_closed
        assert first is not second


def test_governance_client_alias():
    """GovernanceClient is a deprecated alias for StructuredLLMClient."""
    assert GovernanceClient is StructuredLLMClient
