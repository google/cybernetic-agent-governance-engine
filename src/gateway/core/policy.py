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
from datetime import datetime
from decimal import Decimal
from typing import Any

import httpx
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from config.settings import Config
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.observability.attributes import (
    OBSERVATION_INPUT,
    OBSERVATION_NAME,
    OBSERVATION_TYPE,
    TRACE_METADATA_GOVERNANCE_ACTION,
    TRACE_METADATA_GOVERNANCE_DECISION,
    TRACE_METADATA_GOVERNANCE_DENIAL_REASON,
    TRACE_METADATA_GOVERNANCE_OPA_URL,
    TRACE_METADATA_GOVERNANCE_POLICY_INPUT_SIZE,
    TRACE_METADATA_ISO_CONTROL_ID,
    TRACE_METADATA_ISO_REQUIREMENT,
    TRACE_METADATA_LATENCY_CURRENCY_TAX,
)

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
# Identical OPA inputs (same action+symbol+amount) within a
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
    """Return a deterministic Redis key for an OPA input payload.

    v3.1.0: Migrated to RFC 8785 JCS canonicalization with pre-normalization.
    """

    # Normalize datetime/Decimal before JCS canonicalization
    def _normalize(obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, Decimal):
            return str(obj)
        elif isinstance(obj, dict):
            return {k: _normalize(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [_normalize(item) for item in obj]
        elif isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        else:
            return str(obj)

    normalized = _normalize(input_data)
    canonical_bytes = jcs_canonicalize_plan(normalized)
    digest = hashlib.sha256(canonical_bytes).hexdigest()[:24]
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
            # Build the explain URL — same decision path as the hot path, plus
            # ?explain=full. Config is re-read here (not cached) so test
            # overrides work.
            base_url, uds_path = _opa_endpoint()
            explain_url = (
                f"{base_url}{_decision_path(_active_opa_package())}?explain=full"
            )
            if uds_path:
                transport = httpx.AsyncHTTPTransport(uds=uds_path)
            else:
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

    Thread-safety: Uses asyncio.Lock to protect shared mutable state
    (failures, state, last_failure_time) from race conditions when
    multiple concurrent coroutines call record_failure/record_success.
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
        self._lock = asyncio.Lock()

    async def record_failure(self) -> None:
        """Record a failure and potentially open the circuit breaker.

        Thread-safe: Uses asyncio.Lock to prevent race conditions
        on the read-modify-write of failures counter and state transitions.
        """
        async with self._lock:
            self.failures += 1
            self.last_failure_time = time.time()
            if self.state == "CLOSED" and self.failures >= self.failure_threshold:
                self.state = "OPEN"
                logger.warning(
                    f"🔥 Circuit Breaker OPENED after {self.failures} failures."
                )

    async def record_success(self) -> None:
        """Record a success and potentially close the circuit breaker.

        Thread-safe: Uses asyncio.Lock to prevent race conditions
        on state transitions from HALF_OPEN to CLOSED.
        """
        async with self._lock:
            if self.state == "OPEN":
                logger.info("✅ Circuit Breaker RECOVERED (CLOSED).")
            elif self.state == "HALF_OPEN":
                logger.info("✅ Circuit Breaker recovered from HALF_OPEN → CLOSED.")
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


class OPAPolicyMismatchError(RuntimeError):
    """OPA is unreachable or lacks the active domain's package or rules."""


def _opa_endpoint() -> tuple[str, str | None]:
    """Return ``(base_url, uds_socket_path)`` parsed from ``OPA_URL``.

    ``OPA_URL`` must be a base URL (``http(s)://host:port`` or
    ``http+unix://<quoted socket path>``) with no path: the decision path is
    owned by the active domain (``DomainConfig.opa_package``), so a path here
    would let a deployment point the kernel at another domain's policy.

    Raises:
        RuntimeError: ``OPA_URL`` unset, carrying a path/query, or using an
            unsupported scheme.
    """
    raw = Config.OPA_URL
    if not raw:
        raise RuntimeError("FAIL-CLOSED: OPA_URL is not set")
    parsed = urllib.parse.urlparse(raw)
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise RuntimeError(
            f"FAIL-CLOSED: OPA_URL must be a base URL without a path (got {parsed.path!r}); "
            "the decision path comes from the active domain's DomainConfig.opa_package"
        )
    if parsed.scheme == "http+unix":
        return "http://localhost", urllib.parse.unquote(parsed.netloc)
    if parsed.scheme not in ("http", "https"):
        raise RuntimeError(
            f"FAIL-CLOSED: OPA_URL scheme must be http, https or http+unix, got {parsed.scheme!r}"
        )
    return f"{parsed.scheme}://{parsed.netloc}", None


def _decision_path(package: str) -> str:
    """``trade.governance`` → ``/v1/data/trade/governance``."""
    return "/v1/data/" + package.replace(".", "/")


def _active_opa_package() -> str:
    from src.gateway.governance.plugin_loader import active_domain_config

    return active_domain_config().opa_package


def _rules_in_package(modules: list[dict[str, Any]], package: str) -> set[str] | None:
    """Rule names defined in ``package`` across OPA ``/v1/policies`` modules.

    Returns ``None`` if no loaded module declares ``package``. A package may
    span several modules, so rules are unioned.
    """
    target = ["data", *package.split(".")]
    found = False
    rules: set[str] = set()
    for module in modules:
        ast = module.get("ast") or {}
        path = [
            term.get("value") for term in (ast.get("package") or {}).get("path", [])
        ]
        if path != target:
            continue
        found = True
        for rule in ast.get("rules") or []:
            head = rule.get("head") or {}
            # OPA < 1.0 sets head.name; OPA >= 1.0 sets head.ref[0].value.
            name = head.get("name") or ((head.get("ref") or [{}])[0].get("value"))
            if isinstance(name, str):
                rules.add(name)
    return rules if found else None


class OPAClient:
    """
    Async OPA Client with Circuit Breaker.

    Queries ``OPA_URL`` + ``/v1/data/<package>``, where ``package`` defaults to
    the active domain's ``DomainConfig.opa_package``. ``OPA_URL`` is parsed at
    construction; a malformed value is recorded rather than raised (the
    client is built at import time) and every later use fails closed.
    """

    def __init__(self, package: str | None = None):  # type: ignore[no-untyped-def]
        self.url = Config.OPA_URL  # raw value, for tracing only
        self.auth_token = Config.OPA_AUTH_TOKEN
        self.cb = CircuitBreaker()
        self._package = package
        # HIGH-7 fix: pooled httpx.AsyncClient — created once, reused across requests.
        self._http_client: httpx.AsyncClient | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._endpoint: tuple[str, str | None] | None = None
        self._endpoint_error: RuntimeError | None = None
        try:
            self._endpoint = _opa_endpoint()
        except RuntimeError as exc:
            self._endpoint_error = exc
            logger.error(
                "OPAClient misconfigured; every OPA call will fail closed: %s", exc
            )

    def _resolve_endpoint(self) -> tuple[str, str | None]:
        if self._endpoint is None:
            raise self._endpoint_error or RuntimeError(
                "FAIL-CLOSED: OPA endpoint unresolved"
            )
        return self._endpoint

    @property
    def package(self) -> str:
        """Rego package queried: the explicit one, else the active domain's."""
        return self._package or _active_opa_package()

    @property
    def target_url(self) -> str:
        """Decision URL. Raises if ``OPA_URL`` is malformed or no domain is active."""
        base, _ = self._resolve_endpoint()
        return f"{base}{_decision_path(self.package)}"

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
            _, uds_socket_path = self._resolve_endpoint()
            if uds_socket_path:
                transport = httpx.AsyncHTTPTransport(uds=uds_socket_path)
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

    async def close(self) -> None:
        """Close the pooled httpx client and release connections."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None

    async def verify_domain_policy(
        self, package: str, required_rules: tuple[str, ...]
    ) -> None:
        """Fail closed unless OPA has ``package`` loaded with every required rule.

        Lists ``GET {base}/v1/policies`` and inspects each module's parsed AST,
        so the check works whether policies were loaded from files or bundles
        (policy IDs are file paths and are not checked).

        Raises:
            OPAPolicyMismatchError: OPA unreachable, non-2xx, malformed payload,
                package not loaded, or a required rule missing.
        """
        try:
            base, _ = self._resolve_endpoint()
            headers = {}
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"
            response = await self._get_client().get(
                f"{base}/v1/policies", headers=headers, timeout=5.0
            )
            response.raise_for_status()
            modules = response.json()["result"]
            defined = _rules_in_package(modules, package)
        except Exception as exc:
            raise OPAPolicyMismatchError(
                f"cannot verify OPA package {package!r}: {exc}"
            ) from exc
        if defined is None:
            raise OPAPolicyMismatchError(
                f"OPA has no module declaring package {package!r}"
            )
        missing = sorted(set(required_rules) - defined)
        if missing:
            raise OPAPolicyMismatchError(
                f"OPA package {package!r} lacks required rules {missing}"
            )
        logger.info(
            "✅ OPA package %s verified (rules: %s)", package, ", ".join(required_rules)
        )

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
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "opa_policy_check")
            span.set_attribute(OBSERVATION_INPUT, json.dumps(input_data))
            start_time = time.time()
            span.set_attribute(TRACE_METADATA_ISO_CONTROL_ID, "A.10.1")
            span.set_attribute(
                TRACE_METADATA_ISO_REQUIREMENT,
                "Transparency & Explainability",
            )
            span.set_attribute(TRACE_METADATA_GOVERNANCE_OPA_URL, self.url)  # type: ignore[arg-type]
            span.set_attribute(
                TRACE_METADATA_GOVERNANCE_ACTION,
                input_data.get("action", "unknown"),
            )
            span.set_attribute(
                TRACE_METADATA_GOVERNANCE_POLICY_INPUT_SIZE,
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
                    TRACE_METADATA_LATENCY_CURRENCY_TAX, governance_tax_ms
                )

                response.raise_for_status()
                await self.cb.record_success()

                resp_json = response.json()
                raw_result = resp_json.get("result", "DENY")
                explanation = resp_json.get("explanation", [])

                # ── Normalize OPA result to canonical decision string ────────
                # OPA policies can return various types:
                #   - dict: {"allow": true, "reasons": [...]} or {"decision": "ALLOW"}
                #   - bool: true/false
                #   - str: "ALLOW"/"DENY"/"MANUAL_REVIEW"
                # We normalize all variants to a canonical uppercase string.
                if isinstance(raw_result, dict):
                    # Extract decision from dict response (common OPA patterns)
                    decision = raw_result.get(
                        "allow", raw_result.get("decision", "DENY")
                    )
                    if isinstance(decision, bool):
                        decision_str = "ALLOW" if decision else "DENY"
                    else:
                        decision_str = str(decision).upper()
                elif isinstance(raw_result, bool):
                    decision_str = "ALLOW" if raw_result else "DENY"
                else:
                    decision_str = (
                        str(raw_result).upper() if raw_result is not None else "DENY"
                    )

                span.set_attribute(TRACE_METADATA_GOVERNANCE_DECISION, decision_str)

                # Return the decision string (documented API).
                # The explanation is logged for the Auditor via the OTel span above.
                logger.debug(
                    "OPA explanation entries: %d",
                    len(explanation) if isinstance(explanation, list) else 0,
                )

                # ── Write cache (non-blocking, fire-and-forget) ──────────────
                # Only cache deterministic decisions (ALLOW/DENY/MANUAL_REVIEW).
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

                return decision_str

            except Exception as e:
                await self.cb.record_failure()
                logger.critical(f"🔥 OPA FAILURE: {e}")
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR))
                span.set_attribute(
                    TRACE_METADATA_GOVERNANCE_DENIAL_REASON, "SYSTEM_FAILURE"
                )
                return "DENY"
