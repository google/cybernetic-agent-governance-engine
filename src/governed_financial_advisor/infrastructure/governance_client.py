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
StructuredLLMClient — Structured output generation via guided JSON / vLLM.

Produces Pydantic-validated structured outputs by calling the vLLM inference
endpoint with guided_json constraints.

R-19 Fix: Uses a singleton pooled AsyncClient (max_connections=20,
max_keepalive_connections=10, keepalive_expiry=30s) initialised lazily on
first use behind an asyncio.Lock to prevent race conditions.  Transient HTTP
errors (429, 503) are retried up to 3 times with exponential back-off starting
at 1 s.
"""

import asyncio
import logging
import os
from typing import TypeVar

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

# ---------------------------------------------------------------------------
# Module-level singleton state
# ---------------------------------------------------------------------------

_async_client: httpx.AsyncClient | None = None
_async_client_lock: asyncio.Lock = asyncio.Lock()

# Connection pool configuration (R-19)
_POOL_LIMITS = httpx.Limits(
    max_connections=20,
    max_keepalive_connections=10,
    keepalive_expiry=30,
)

# Retry configuration (R-19)
_MAX_RETRIES: int = 3
_BASE_DELAY_SECONDS: float = 1.0
_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 503})


async def _get_async_client(timeout: float = 30.0) -> httpx.AsyncClient:
    """Return the module-level singleton AsyncClient, creating it lazily.

    Uses asyncio.Lock to prevent concurrent first-call initialisation races.
    The timeout parameter is only used during the initial creation; subsequent
    calls return the already-created client (callers can override per-request
    via request-level timeout if needed).
    """
    global _async_client
    if _async_client is not None and not _async_client.is_closed:
        return _async_client

    async with _async_client_lock:
        # Double-checked locking
        if _async_client is not None and not _async_client.is_closed:
            return _async_client
        logger.info(
            "GovernanceClient: initialising pooled AsyncClient "
            "(max_connections=20, max_keepalive=10, keepalive_expiry=30s)"
        )
        _async_client = httpx.AsyncClient(
            limits=_POOL_LIMITS,
            timeout=timeout,
        )
        return _async_client


async def close_async_client() -> None:
    """Gracefully close the singleton AsyncClient (call on application shutdown)."""
    global _async_client
    if _async_client is not None and not _async_client.is_closed:
        logger.info("GovernanceClient: closing pooled AsyncClient")
        await _async_client.aclose()
        _async_client = None


# ---------------------------------------------------------------------------
# Retry helper
# ---------------------------------------------------------------------------


async def _post_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    json: dict,
    headers: dict,
) -> httpx.Response:
    """POST with exponential back-off for transient HTTP errors (429, 503).

    Raises the last exception if all retries are exhausted.
    """
    last_exc: Exception | None = None
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            response = await client.post(url, json=json, headers=headers)
            if response.status_code not in _RETRYABLE_STATUS_CODES:
                response.raise_for_status()
                return response
            # Transient error — back off and retry
            delay = _BASE_DELAY_SECONDS * (2 ** (attempt - 1))
            logger.warning(
                "GovernanceClient: received %s (attempt %d/%d), retrying in %.1fs",
                response.status_code,
                attempt,
                _MAX_RETRIES,
                delay,
            )
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(delay)
            last_exc = httpx.HTTPStatusError(
                f"HTTP {response.status_code}",
                request=response.request,
                response=response,
            )
        except (
            httpx.ConnectError,
            httpx.TimeoutException,
            httpx.RemoteProtocolError,
        ) as exc:
            delay = _BASE_DELAY_SECONDS * (2 ** (attempt - 1))
            logger.warning(
                "GovernanceClient: network error on attempt %d/%d (%s), retrying in %.1fs",
                attempt,
                _MAX_RETRIES,
                exc,
                delay,
            )
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(delay)
            last_exc = exc
    raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# GovernanceClient
# ---------------------------------------------------------------------------


class StructuredLLMClient:
    """
    StructuredLLMClient — Structured output generation via guided JSON / vLLM.

    Produces Pydantic-validated structured outputs by calling the vLLM inference
    endpoint with guided_json constraints.

    Previously named GovernanceClient (misleading — this class has no OPA/policy logic).
    The name GovernanceClient is retained as a deprecated alias for backward compatibility.

    For HTTP connection pooling, see: src.governed_financial_advisor.infrastructure.http_pool
    """

    # Default to the "Goldilocks" model: 7B parameters, fits on L4
    DEFAULT_MODEL_ID = os.environ.get("VLLM_FAST_MODEL") or os.environ.get("MODEL_FAST")

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str = None,
        model_name: str | None = None,
        timeout_seconds: float = 30.0,
    ):
        """
        Initializes the StructuredLLMClient for structured vLLM generation.

        Args:
            base_url: The internal cluster URL for the vLLM service.
            api_key: API key for vLLM (usually EMPTY for internal).
            model_name: Model name to request from vLLM.
            timeout_seconds: Request timeout (used for singleton client init).
        """
        from config.settings import Config

        self.base_url = base_url or os.getenv(
            "GATEWAY_API_BASE", Config.GATEWAY_API_BASE
        )
        api_key = api_key or os.environ.get("VLLM_API_KEY", "EMPTY")
        self.api_key = api_key
        # Prioritize init arg, then env var, then class constant
        self.model_name = model_name or os.getenv("VLLM_MODEL", self.DEFAULT_MODEL_ID)
        self.timeout = timeout_seconds

    def _prepare_request(
        self, prompt: str, schema: type[T], system_instruction: str
    ) -> dict:
        """Helper to prepare the request payload."""
        json_schema = schema.model_json_schema()
        return {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.0,
            "guided_json": json_schema,
            "max_tokens": 4096,  # Increased for complex risk reports
        }

    async def generate_structured(
        self,
        prompt: str,
        schema: type[T],
        system_instruction: str = "You are a strict governance engine.",
    ) -> T:
        """
        Generates a structured response strictly adhering to the provided Pydantic schema (Async).

        Uses the module-level pooled singleton AsyncClient with retry logic for
        transient HTTP errors (429, 503).
        """
        payload = self._prepare_request(prompt, schema, system_instruction)
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        url = f"{self.base_url}/chat/completions"

        logger.info(
            "Sending Governed Request (Async) to %s with schema %s",
            url,
            schema.__name__,
        )

        client = await _get_async_client(self.timeout)
        try:
            response = await _post_with_retry(
                client, url, json=payload, headers=headers
            )
            result_data = response.json()
            content = result_data["choices"][0]["message"]["content"]
            return schema.model_validate_json(content)
        except Exception as e:
            logger.error("Governance Validation Error: %s", e)
            raise

    def generate_structured_sync(
        self,
        prompt: str,
        schema: type[T],
        system_instruction: str = "You are a strict governance engine.",
    ) -> T:
        """
        Generates a structured response strictly adhering to the provided Pydantic schema (Sync).
        Use this when calling from synchronous tool functions to avoid event loop conflicts.

        Note: The sync path uses a short-lived httpx.Client (not the async pool) because
        mixing async and sync clients in the same pool is not supported by httpx.
        Retry logic with exponential back-off is applied for transient HTTP errors.
        """
        payload = self._prepare_request(prompt, schema, system_instruction)
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        url = f"{self.base_url}/chat/completions"

        logger.info(
            "Sending Governed Request (Sync) to %s with schema %s", url, schema.__name__
        )

        import time

        with httpx.Client(timeout=self.timeout) as client:
            last_exc: Exception | None = None
            for attempt in range(1, _MAX_RETRIES + 1):
                try:
                    response = client.post(url, json=payload, headers=headers)
                    if response.status_code not in _RETRYABLE_STATUS_CODES:
                        response.raise_for_status()
                        result_data = response.json()
                        content = result_data["choices"][0]["message"]["content"]
                        return schema.model_validate_json(content)
                    delay = _BASE_DELAY_SECONDS * (2 ** (attempt - 1))
                    logger.warning(
                        "GovernanceClient (sync): received %s (attempt %d/%d), retrying in %.1fs",
                        response.status_code,
                        attempt,
                        _MAX_RETRIES,
                        delay,
                    )
                    if attempt < _MAX_RETRIES:
                        time.sleep(delay)
                    last_exc = httpx.HTTPStatusError(
                        f"HTTP {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                except Exception as e:
                    logger.error("Governance Validation Error: %s", e)
                    last_exc = e
                    if attempt < _MAX_RETRIES:
                        time.sleep(_BASE_DELAY_SECONDS * (2 ** (attempt - 1)))
            raise last_exc  # type: ignore[misc]

    # ------------------------------------------------------------------
    # Lifespan helpers
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the shared async client pool (call on application shutdown)."""
        await close_async_client()


GovernanceClient = StructuredLLMClient  # Deprecated alias
