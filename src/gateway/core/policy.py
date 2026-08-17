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

import asyncio
import hashlib
import json
import logging
import os
import time
import urllib.parse
from typing import Any

import httpx
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from config.settings import Config

logger = logging.getLogger("Gateway.Policy")
tracer = trace.get_tracer("gateway.policy")

# ---------------------------------------------------------------------------
# OPA Explain-Mode Async Background Logging
# ---------------------------------------------------------------------------
# When CAGE_OPA_EXPLAIN_LOGGING=true, every successful OPA evaluation enqueues
# a (policy_path, input_data, decision) tuple onto _explain_queue.  A
# background coroutine (_explain_worker) dequeues these tuples and makes a
# separate HTTP request to OPA with ?explain=full to fetch the full policy
# evaluation trace, logging it at DEBUG level.
#
# The hot path (evaluate_policy) is NEVER delayed by explain requests:
#   - Enqueue is non-blocking (put_nowait).
#   - If the queue is full, the explain request is silently dropped.
#   - The background worker runs independently on the event loop.
#
# Enable with: CAGE_OPA_EXPLAIN_LOGGING=true
# Default: false (disabled — explain=full adds significant OPA overhead).
CAGE_OPA_EXPLAIN_LOGGING: bool = (
    os.getenv("CAGE_OPA_EXPLAIN_LOGGING", "false").lower() == "true"
)

# Module-level singleton queue for buffering explain requests.
# maxsize=1000 caps memory usage; overflow is dropped (never blocks hot path).
_explain_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

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


async def _read_opa_cache(key: str) -> str | None:
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


# ---------------------------------------------------------------------------
# OPA Explain-Mode Background Worker
# ---------------------------------------------------------------------------


async def _explain_worker() -> None:
    """Background coroutine that fetches OPA explain=full traces asynchronously.

    Dequeues ``(policy_path, input_data, decision)`` tuples from
    ``_explain_queue`` and makes a separate HTTP request to OPA with
    ``?explain=full`` appended to the URL.  The full explanation is logged at
    DEBUG level (truncated to 500 chars to avoid log flooding).

    This coroutine runs indefinitely until cancelled.  It never raises — all
    connection errors are caught and logged as WARNING, then the worker
    continues processing the next item.

    IMPORTANT: This worker must NOT be awaited on the hot path.  It is
    scheduled as a background task via ``start_explain_worker()``.
    """
    logger.info(
        "OPA explain-mode worker started (queue maxsize=%d).", _explain_queue.maxsize
    )
    while True:
        try:
            policy_path, input_data, decision = await _explain_queue.get()
        except asyncio.CancelledError:
            logger.info("OPA explain-mode worker cancelled — shutting down.")
            return

        try:
            # Build the explain URL — append ?explain=full to the OPA target URL.
            # We re-read Config here (not cached) so that test overrides work.
            opa_url = Config.OPA_URL
            parsed = urllib.parse.urlparse(opa_url)

            if parsed.scheme == "http+unix":
                uds_path = urllib.parse.unquote(parsed.netloc)
                explain_url = f"http://localhost{parsed.path}?explain=full"
                transport = httpx.AsyncHTTPTransport(uds=uds_path)
            else:
                explain_url = f"{opa_url}?explain=full"
                transport = httpx.AsyncHTTPTransport(retries=0)

            auth_token = Config.OPA_AUTH_TOKEN
            headers: dict = {}
            if auth_token:
                headers["Authorization"] = f"Bearer {auth_token}"

            async with httpx.AsyncClient(transport=transport) as client:
                response = await client.post(
                    explain_url,
                    json={"input": input_data},
                    headers=headers,
                    timeout=10.0,
                )
                response.raise_for_status()
                resp_json = response.json()
                explanation = resp_json.get("explanation", [])
                explanation_str = json.dumps(explanation)[:500]  # truncate to 500 chars

            logger.debug(
                "OPA explain (policy=%s decision=%s): %s",
                policy_path,
                decision,
                explanation_str,
            )

        except asyncio.CancelledError:
            logger.info(
                "OPA explain-mode worker cancelled during HTTP request — shutting down."
            )
            _explain_queue.task_done()
            return
        except Exception as exc:
            logger.warning(
                "OPA explain-mode worker: failed to fetch explanation "
                "(policy=%s decision=%s): %s",
                policy_path,
                decision,
                exc,
            )
        finally:
            try:
                _explain_queue.task_done()
            except ValueError:
                pass  # task_done() called more times than get() — ignore


def start_explain_worker(loop: asyncio.AbstractEventLoop) -> asyncio.Task:
    """Schedule ``_explain_worker()`` as a background task on *loop*.

    Call this once at application startup (e.g. in the FastAPI lifespan handler
    or after ``asyncio.get_event_loop()`` is established).

    Args:
        loop: The running event loop on which to schedule the worker.

    Returns:
        The ``asyncio.Task`` wrapping the worker coroutine.  The caller may
        store a reference to prevent garbage collection, but the task runs
        independently and does not need to be awaited.
    """
    task = loop.create_task(_explain_worker(), name="opa_explain_worker")
    logger.info(
        "OPA explain-mode background worker scheduled (task=%s).", task.get_name()
    )
    return task


class CircuitBreaker:
    """
    Implements a Fail-Fast Circuit Breaker pattern.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 30,
        max_latency_budget: int = 3000,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.max_latency_budget = max_latency_budget
        self.failures = 0
        self.last_failure_time = 0.0
        self.state = "CLOSED"

    def record_failure(self):  # type: ignore[no-untyped-def]
        self.failures += 1
        self.last_failure_time = time.time()
        if self.state == "CLOSED" and self.failures >= self.failure_threshold:
            self.state = "OPEN"
            logger.warning(f"🔥 Circuit Breaker OPENED after {self.failures} failures.")

    def record_success(self):  # type: ignore[no-untyped-def]
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

    def check_soft_ceiling(
        self, cumulative_spend_ms: float, soft_ceiling_ms: float = 2000.0
    ) -> bool:
        if cumulative_spend_ms > soft_ceiling_ms:
            return True
        return False


class OPAClient:
    """
    Async OPA Client with Circuit Breaker.
    """

    # Default OPA data path for the trade governance policy.
    # OPA's REST API requires POST /v1/data/<package_path> to evaluate a policy.
    # When OPA_URL is set to a bare host (e.g. http://localhost:8181) without a
    # path, the client appends this default so the request reaches the correct
    # policy package (trade.governance → /v1/data/trade/governance).
    # Override by including the full path in OPA_URL, e.g.:
    #   OPA_URL=http://localhost:8181/v1/data/trade/governance
    _DEFAULT_DATA_PATH: str = "/v1/data/trade/governance"

    def __init__(self):  # type: ignore[no-untyped-def]
        self.url = Config.OPA_URL
        self.auth_token = Config.OPA_AUTH_TOKEN
        self.cb = CircuitBreaker()
        self._uds_socket_path: str | None = None
        # HIGH-7 fix: pooled httpx.AsyncClient — created once, reused across requests.
        # The previous _make_client() created a new client per request, exhausting
        # file descriptors under load.  The client is lazily initialised on first use
        # and closed via close() during application shutdown.
        self._http_client: httpx.AsyncClient | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

        parsed = urllib.parse.urlparse(self.url)
        if parsed.scheme == "http+unix":
            self._uds_socket_path = urllib.parse.unquote(parsed.netloc)
            # UDS: path is the socket path; append default data path for policy eval.
            uds_path_part = parsed.path or self._DEFAULT_DATA_PATH
            if not uds_path_part.startswith("/v1/data"):
                uds_path_part = self._DEFAULT_DATA_PATH
            self.target_url = f"http://localhost{uds_path_part}"
            logger.info(f"🔌 OPAClient configured for UDS: {self._uds_socket_path}")
        else:
            # HTTP: if OPA_URL has no path (or only "/"), append the default data path
            # so that evaluate_policy() POSTs to the correct OPA REST endpoint.
            if not parsed.path or parsed.path in ("", "/"):
                base = f"{parsed.scheme}://{parsed.netloc}"  # type: ignore[str-bytes-safe]  # urlparse scheme/netloc are str when input is str
                self.target_url = f"{base}{self._DEFAULT_DATA_PATH}"
                logger.info(
                    "🌐 OPAClient configured for HTTP: %s "
                    "(appended default data path %s to bare OPA_URL)",
                    self.target_url,
                    self._DEFAULT_DATA_PATH,
                )
            else:
                self.target_url = self.url  # type: ignore[assignment]
                logger.info(f"🌐 OPAClient configured for HTTP: {self.target_url}")

    def _get_client(self) -> httpx.AsyncClient:
        """Return (or lazily create) the shared pooled httpx.AsyncClient.

        HIGH-7 fix: replaces _make_client() which created a new client per
        request.  The pooled client reuses TCP connections (keep-alive) and
        avoids file-descriptor exhaustion under load.
        """
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if (
            self._http_client is None
            or self._http_client.is_closed
            or (self._loop is not None and self._loop != current_loop)
            or (self._loop is not None and self._loop.is_closed())
        ):
            self._loop = current_loop
            if self._uds_socket_path:
                transport = httpx.AsyncHTTPTransport(uds=self._uds_socket_path)
            else:
                transport = httpx.AsyncHTTPTransport(retries=0)
            self._http_client = httpx.AsyncClient(
                transport=transport,
                limits=httpx.Limits(
                    max_connections=20,
                    max_keepalive_connections=10,
                    keepalive_expiry=30,
                ),
                timeout=httpx.Timeout(connect=2.0, read=5.0, write=5.0, pool=2.0),
            )
        return self._http_client

    async def close(self):  # type: ignore[no-untyped-def]
        """Close the pooled httpx client and release connections."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None

    async def check_policy_exists(self, policy_path: str) -> bool:
        """Check whether a named policy is loaded in OPA via the policy management API.

        Makes an HTTP GET to ``{opa_base_url}/v1/policies/{policy_path}`` and
        returns ``True`` if OPA responds with HTTP 200 (policy found), ``False``
        for any other status code or if OPA is unreachable.

        Args:
            policy_path: The OPA policy ID to probe, e.g. ``"trade/governance"``.

        Returns:
            ``True`` if the policy is present and OPA is reachable, ``False`` otherwise.
        """
        try:
            # Derive the OPA base URL (strip any configured policy path suffix)
            parsed = urllib.parse.urlparse(self.url)
            if parsed.scheme == "http+unix":
                base_url = "http://localhost"
            else:
                base_url = f"{parsed.scheme}://{parsed.netloc}"  # type: ignore[str-bytes-safe]  # urlparse scheme/netloc are str when input is str

            probe_url = f"{base_url}/v1/policies/{policy_path}"

            headers = {}
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"

            client = self._get_client()
            response = await client.get(probe_url, headers=headers, timeout=5.0)

            return response.status_code == 200
        except Exception as exc:
            logger.debug("check_policy_exists(%r) failed: %s", policy_path, exc)
            return False

    async def evaluate_policy(
        self, input_data: dict[str, Any], current_latency_ms: float = 0.0
    ) -> str:
        if not self.cb.can_execute():
            logger.warning("⚠️ Circuit Breaker OPEN. Fast failing OPA check -> DENY.")
            return "DENY"

        if self.cb.is_bankrupt(current_latency_ms):
            logger.critical(
                f"💀 Bankruptcy Protocol: {current_latency_ms}ms > {self.cb.max_latency_budget}ms."
            )
            return "DENY"

        if self.cb.check_soft_ceiling(current_latency_ms):
            logger.warning(
                f"📉 Latency Inflation Warning: {current_latency_ms}ms > 2000ms."
            )

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
            span.set_attribute(
                "langfuse.trace.metadata.iso.requirement",
                "Transparency & Explainability",
            )
            span.set_attribute("langfuse.trace.metadata.governance.opa_url", self.url)  # type: ignore[arg-type]
            span.set_attribute(
                "langfuse.trace.metadata.governance.action",
                input_data.get("action", "unknown"),
            )
            span.set_attribute(
                "langfuse.trace.metadata.governance.policy_input_size",
                len(json.dumps(input_data)),
            )
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
                #
                # Explain-mode logging is async and non-blocking — the hot path is
                # never delayed by explain requests.  See _explain_worker() and
                # start_explain_worker() for the background explain architecture.
                query_url = self.target_url

                # HIGH-7 fix: use the pooled client — no new client per request.
                client = self._get_client()
                response = await client.post(
                    query_url,
                    json={"input": input_data},
                    headers=headers,
                    timeout=5.0,
                )

                governance_tax_ms = (time.time() - start_time) * 1000
                span.set_attribute(
                    "langfuse.trace.metadata.latency_currency_tax", governance_tax_ms
                )

                response.raise_for_status()
                self.cb.record_success()

                resp_json = response.json()
                result = resp_json.get("result", "DENY")
                explanation = resp_json.get("explanation", [])

                span.set_attribute(
                    "langfuse.trace.metadata.governance.decision", str(result)
                )

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

                # ── Async explain-mode logging (non-blocking) ────────────────
                # If CAGE_OPA_EXPLAIN_LOGGING is enabled, enqueue the policy
                # path, input, and decision for background explain=full fetching.
                # put_nowait() is used so the hot path is never blocked.
                # If the queue is full, the explain request is silently dropped.
                # Explain-mode logging is async and non-blocking — the hot path
                # is never delayed by explain requests.
                if CAGE_OPA_EXPLAIN_LOGGING:
                    policy_path = input_data.get("action", "unknown")
                    try:
                        _explain_queue.put_nowait(
                            (policy_path, input_data, decision_str)
                        )
                    except asyncio.QueueFull:
                        logger.warning(
                            "OPA explain queue full (maxsize=%d) — dropping explain "
                            "request for policy=%s decision=%s.",
                            _explain_queue.maxsize,
                            policy_path,
                            decision_str,
                        )

                return result

            except Exception as e:
                self.cb.record_failure()
                logger.critical(f"🔥 OPA FAILURE: {e}")
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR))
                span.set_attribute(
                    "langfuse.trace.metadata.governance.denial_reason", "SYSTEM_FAILURE"
                )
                return "DENY"
