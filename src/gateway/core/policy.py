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
Gateway Core: Policy & Governance (OPA + CircuitBreaker)
"""

import logging
import os
import time
import hashlib
import urllib.parse
import json
from typing import Any, Optional

import httpx
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from config.settings import Config

logger = logging.getLogger("Gateway.Policy")
tracer = trace.get_tracer("gateway.policy")

# ---------------------------------------------------------------------------
# OPA Decision Cache — short-TTL Redis cache for identical policy inputs
# ---------------------------------------------------------------------------
# Identical OPA inputs (same action+symbol+amount+slm_available) within a
# 10-second window return the cached decision without an HTTP round-trip.
# TTL is intentionally short to avoid stale decisions under fast market moves.
#
# Controlled by OPA_CACHE_ENABLED env var (default: "true").
# Set OPA_CACHE_ENABLED=false to disable (e.g. in unit test environments).
_OPA_CACHE_TTL_SECONDS: int = 10
_OPA_CACHE_PREFIX: str = "cage:opa:decision:"


def _opa_cache_enabled() -> bool:
    """Return True if the OPA decision cache is active."""
    return os.environ.get("OPA_CACHE_ENABLED", "true").lower() == "true"


def _opa_cache_key(input_data: dict) -> str:
    """Return a deterministic Redis key for an OPA input payload."""
    # Sort keys for deterministic serialisation regardless of dict insertion order
    canonical = json.dumps(input_data, sort_keys=True, default=str)
    digest = hashlib.sha256(canonical.encode()).hexdigest()[:24]
    return f"{_OPA_CACHE_PREFIX}{digest}"


async def _read_opa_cache(key: str) -> Optional[str]:
    """Return cached OPA decision string, or None if absent/unavailable/disabled."""
    if not _opa_cache_enabled():
        return None
    try:
        from src.gateway.infrastructure.redis_client import redis_client
        if redis_client is None:
            return None
        val = await redis_client.get(key)
        return val.decode() if isinstance(val, bytes) else val
    except Exception:
        return None


async def _write_opa_cache(key: str, decision: str) -> None:
    """Write an OPA decision to Redis with the configured TTL."""
    if not _opa_cache_enabled():
        return
    try:
        from src.gateway.infrastructure.redis_client import redis_client
        if redis_client is None:
            return
        await redis_client.setex(key, _OPA_CACHE_TTL_SECONDS, decision)
    except Exception:
        pass  # Cache write failure is silent — OPA HTTP path remains authoritative


class CircuitBreaker:
    """
    Implements a Fail-Fast Circuit Breaker pattern.
    """
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 30, max_latency_budget: int = 3000):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.max_latency_budget = max_latency_budget
        self.failures = 0
        self.last_failure_time = 0.0
        self.state = "CLOSED"

    def record_failure(self):
        self.failures += 1
        self.last_failure_time = time.time()
        if self.state == "CLOSED" and self.failures >= self.failure_threshold:
            self.state = "OPEN"
            logger.warning(f"🔥 Circuit Breaker OPENED after {self.failures} failures.")

    def record_success(self):
        if self.state == "OPEN":
            logger.info("✅ Circuit Breaker RECOVERED (CLOSED).")
        self.failures = 0
        self.state = "CLOSED"

    def can_execute(self) -> bool:
        if self.state == "CLOSED":
            return True
        if time.time() - self.last_failure_time > self.recovery_timeout:
            return True
        return False

    def is_bankrupt(self, cumulative_spend_ms: float) -> bool:
        if cumulative_spend_ms > self.max_latency_budget:
            return True
        return False

    def check_soft_ceiling(self, cumulative_spend_ms: float, soft_ceiling_ms: float = 2000.0) -> bool:
        if cumulative_spend_ms > soft_ceiling_ms:
            return True
        return False

class OPAClient:
    """
    Async OPA Client with Circuit Breaker.
    """
    def __init__(self):
        self.url = Config.OPA_URL
        self.auth_token = Config.OPA_AUTH_TOKEN
        self.cb = CircuitBreaker()
        self._uds_socket_path: str | None = None

        parsed = urllib.parse.urlparse(self.url)
        if parsed.scheme == "http+unix":
            self._uds_socket_path = urllib.parse.unquote(parsed.netloc)
            self.target_url = f"http://localhost{parsed.path}"
            logger.info(f"🔌 OPAClient configured for UDS: {self._uds_socket_path}")
        else:
            self.target_url = self.url
            logger.info(f"🌐 OPAClient configured for HTTP: {self.target_url}")

    def _make_client(self) -> httpx.AsyncClient:
        """Create a fresh AsyncClient per request to avoid event-loop lifetime issues."""
        if self._uds_socket_path:
            transport = httpx.AsyncHTTPTransport(uds=self._uds_socket_path)
        else:
            transport = httpx.AsyncHTTPTransport(retries=0)
        return httpx.AsyncClient(transport=transport)

    async def close(self):
        pass  # No persistent client; each request uses its own client via context manager.

    async def evaluate_policy(self, input_data: dict[str, Any], current_latency_ms: float = 0.0) -> str:
        if not self.cb.can_execute():
            logger.warning("⚠️ Circuit Breaker OPEN. Fast failing OPA check -> DENY.")
            return "DENY"

        if self.cb.is_bankrupt(current_latency_ms):
             logger.critical(f"💀 Bankruptcy Protocol: {current_latency_ms}ms > {self.cb.max_latency_budget}ms.")
             return "DENY"

        if self.cb.check_soft_ceiling(current_latency_ms):
            logger.warning(f"📉 Latency Inflation Warning: {current_latency_ms}ms > 2000ms.")

        # ── OPA Decision Cache ──────────────────────────────────────────────
        # Check Redis for a cached decision before making the HTTP call.
        # Short-circuits the entire OPA round-trip for repeated identical inputs
        # within the 10-second TTL window.
        cache_key = _opa_cache_key(input_data)
        cached = await _read_opa_cache(cache_key)
        if cached is not None:
            logger.debug("⚡ OPA cache hit (key=%s…) → %s", cache_key[-8:], cached)
            return cached

        with tracer.start_as_current_span("governance.opa_check") as span:
            span.set_attribute("langfuse.observation.type", "span")
            span.set_attribute("langfuse.observation.name", "opa_policy_check")
            span.set_attribute("langfuse.observation.input", json.dumps(input_data))
            start_time = time.time()
            span.set_attribute("langfuse.trace.metadata.iso.control_id", "A.10.1")
            span.set_attribute("langfuse.trace.metadata.iso.requirement", "Transparency & Explainability")
            span.set_attribute("langfuse.trace.metadata.governance.opa_url", self.url)
            span.set_attribute("langfuse.trace.metadata.governance.action", input_data.get("action", "unknown"))
            span.set_attribute("langfuse.trace.metadata.governance.policy_input_size", len(json.dumps(input_data)))
            span.set_attribute("governance.opa.cache_hit", False)

            headers = {}
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"

            try:
                # IMPORTANT: Do NOT use ?explain=full in the hot governance path.
                # explain=full forces OPA to serialize its full policy evaluation
                # trace (~100KB-1MB JSON), adding 13-17s of latency vs ~30ms without it.
                # The audit trail is captured via OTel span attributes above.
                # Use ?explain=notes for lightweight rule annotations if needed.
                query_url = self.target_url

                # Use a fresh client per request to avoid event-loop lifetime issues
                # (the OPAClient singleton is created at module import time, which may
                # be on a different event loop than the one running the test/request).
                async with self._make_client() as client:
                    response = await client.post(
                        query_url,
                        json={"input": input_data},
                        headers=headers,
                        timeout=5.0,
                    )

                governance_tax_ms = (time.time() - start_time) * 1000
                span.set_attribute("langfuse.trace.metadata.latency_currency_tax", governance_tax_ms)

                response.raise_for_status()
                self.cb.record_success()

                resp_json = response.json()
                result = resp_json.get("result", "DENY")
                explanation = resp_json.get("explanation", [])

                span.set_attribute("langfuse.trace.metadata.governance.decision", str(result))

                # Return the decision string (documented API).
                # The explanation is logged for the Auditor via the OTel span above.
                logger.debug(
                    "OPA explanation entries: %d",
                    len(explanation) if isinstance(explanation, list) else 0,
                )

                # ── Write cache (non-blocking, fire-and-forget) ──────────────
                # Only cache deterministic decisions (ALLOW/DENY/MANUAL_REVIEW).
                # Do not cache None or unexpected types.
                decision_str: str = str(result) if result is not None else "DENY"
                await _write_opa_cache(cache_key, decision_str)

                return result

            except Exception as e:
                self.cb.record_failure()
                logger.critical(f"🔥 OPA FAILURE: {e}")
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR))
                span.set_attribute("langfuse.trace.metadata.governance.denial_reason", "SYSTEM_FAILURE")
                return "DENY"

