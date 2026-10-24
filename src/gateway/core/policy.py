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
import json
import logging
import os
import threading
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any

import httpx
from opentelemetry import trace
from opentelemetry.trace import Span, Status, StatusCode

from config.settings import Config
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


def _normalize_opa_input(obj: Any) -> Any:
    """Normalize datetime/Decimal values into JSON-safe primitives."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, Decimal):
        return str(obj)
    elif isinstance(obj, dict):
        return {k: _normalize_opa_input(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_normalize_opa_input(item) for item in obj]
    elif isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    else:
        return str(obj)


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


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------


class BreakerState(str, Enum):
    """Circuit breaker states."""

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CallOutcome(Enum):
    """What one OPA call showed about OPA's health."""

    #: OPA answered: HTTP 2xx-4xx other than 408 and 429.
    HEALTHY = "healthy"
    #: OPA failed: connect, read or protocol error, HTTP 5xx, 408 or 429.
    UPSTREAM_FAILURE = "upstream_failure"
    #: The call never reached OPA (local pool saturation, misconfiguration,
    #: an unexpected local error) or was cancelled.
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class BreakerTicket:
    """Admission to call OPA; ``probe`` marks the single HALF_OPEN probe."""

    probe: bool


_CALL = BreakerTicket(probe=False)
_PROBE = BreakerTicket(probe=True)


class CircuitBreaker:
    """Fail-fast breaker for the OPA hot path.

    - **CLOSED**: calls flow. ``failure_threshold`` consecutive upstream
      failures open the circuit; a healthy answer resets the count.
    - **OPEN**: calls fail fast until ``recovery_timeout`` seconds have
      passed; the next call then becomes the HALF_OPEN probe.
    - **HALF_OPEN**: only the probe reaches OPA. A healthy answer closes the
      circuit, an upstream failure reopens it, and an inconclusive outcome
      frees the slot for the next caller.

    Only upstream failures count: local pool saturation, misconfiguration
    and requests OPA rejects (4xx) say nothing about OPA's health. Counting
    consecutive failures rather than failures per time window keeps the trip
    rule independent of traffic volume: a dead OPA trips it at any request
    rate, and rare errors between healthy answers never do. Once the circuit
    has opened, outcomes of calls admitted before it are ignored; only the
    probe moves it on.

    Transitions run under a threading lock that is never held across an
    await or while logging, so one breaker is safe across threads and event
    loops. The latency-budget helpers (``is_bankrupt``,
    ``check_soft_ceiling``) are stateless.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        max_latency_budget: int = 3000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.max_latency_budget = max_latency_budget
        self._clock = clock
        self._lock = threading.Lock()
        self._state = BreakerState.CLOSED
        self._failures = 0
        self._opened_at = 0.0
        self._probe_in_flight = False

    @property
    def state(self) -> BreakerState:
        """Current state; HALF_OPEN appears once a probe has been admitted."""
        return self._state

    @property
    def failures(self) -> int:
        """Consecutive upstream failures counted while CLOSED."""
        return self._failures

    def admit(self) -> BreakerTicket | None:
        """Admit one call to OPA, or return ``None`` to fail fast."""
        with self._lock:
            if self._state is BreakerState.CLOSED:
                return _CALL
            if self._state is BreakerState.OPEN:
                if self._clock() - self._opened_at < self.recovery_timeout:
                    return None
                self._state = BreakerState.HALF_OPEN
            if self._probe_in_flight:
                return None
            self._probe_in_flight = True
        logger.info("🔌 Circuit Breaker HALF_OPEN: probing OPA once.")
        return _PROBE

    def record(self, ticket: BreakerTicket, outcome: CallOutcome) -> None:
        """Record what an admitted call showed about OPA's health."""
        with self._lock:
            before = self._state
            self._apply(ticket, outcome)
            after, failures = self._state, self._failures
        if after is before:
            return
        if after is BreakerState.CLOSED:
            logger.info("✅ Circuit Breaker recovered: HALF_OPEN → CLOSED.")
            return
        logger.warning(
            "🔥 Circuit Breaker OPENED (%s); failing fast for %gs.",
            "the HALF_OPEN probe failed"
            if ticket.probe
            else f"{failures} consecutive upstream failures",
            self.recovery_timeout,
        )

    def _apply(self, ticket: BreakerTicket, outcome: CallOutcome) -> None:
        """Apply one outcome to the state machine. Callers hold ``_lock``."""
        if ticket.probe:
            self._probe_in_flight = False
            if outcome is CallOutcome.HEALTHY:
                self._state = BreakerState.CLOSED
                self._failures = 0
            elif outcome is CallOutcome.UPSTREAM_FAILURE:
                self._open()
            return
        if self._state is not BreakerState.CLOSED:
            return  # admitted before the circuit opened; only the probe counts
        if outcome is CallOutcome.HEALTHY:
            self._failures = 0
        elif outcome is CallOutcome.UPSTREAM_FAILURE:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._open()

    def _open(self) -> None:
        """Open the circuit. Callers hold ``_lock``."""
        self._state = BreakerState.OPEN
        self._opened_at = self._clock()

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
        RuntimeError: ``OPA_URL`` unset, carrying a path/query, naming no
            host or socket, or using an unsupported scheme.
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
        socket_path = urllib.parse.unquote(parsed.netloc)
        if not socket_path:
            raise RuntimeError("FAIL-CLOSED: OPA_URL names no socket path")
        return "http://localhost", socket_path
    if parsed.scheme not in ("http", "https"):
        raise RuntimeError(
            f"FAIL-CLOSED: OPA_URL scheme must be http, https or http+unix, got {parsed.scheme!r}"
        )
    if not parsed.hostname:
        raise RuntimeError("FAIL-CLOSED: OPA_URL names no host")
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


def _decision_string(raw_result: Any) -> str:
    """Normalize an OPA ``result`` to a canonical uppercase decision string.

    OPA policies return a dict (``{"allow": true}`` or ``{"decision": "ALLOW"}``),
    a bool, or a string; anything else denies. A dict with neither key, or
    whose ``allow`` and ``decision`` disagree, is ambiguous and denies.
    """
    if isinstance(raw_result, dict):
        answers = {
            _scalar_decision(raw_result[key])
            for key in ("decision", "allow")
            if key in raw_result
        }
        return answers.pop() if len(answers) == 1 else "DENY"
    return _scalar_decision(raw_result)


def _scalar_decision(value: Any) -> str:
    """``True``/``False`` → ``ALLOW``/``DENY``; ``None`` denies; else uppercased."""
    if isinstance(value, bool):
        return "ALLOW" if value else "DENY"
    return str(value).upper() if value is not None else "DENY"


def _deny(span: Span, error: BaseException | str, reason: str) -> str:
    """Log and trace a failed OPA check; the decision is always DENY."""
    logger.critical("🔥 OPA FAILURE (%s): %s", reason, error)
    if isinstance(error, BaseException):
        span.record_exception(error)
    span.set_status(Status(StatusCode.ERROR))
    span.set_attribute(TRACE_METADATA_GOVERNANCE_DENIAL_REASON, reason)
    return "DENY"


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
        """Ask OPA for a decision on ``input_data``; any failure denies.

        Every call goes to OPA: decisions are never cached, so a policy or
        data change takes effect on the next request.
        """
        if self.cb.is_bankrupt(current_latency_ms):
            logger.critical(
                f"💀 Bankruptcy Protocol: {current_latency_ms}ms > {self.cb.max_latency_budget}ms."
            )
            return "DENY"

        if self.cb.check_soft_ceiling(current_latency_ms):
            logger.warning(
                f"📉 Latency Inflation Warning: {current_latency_ms}ms > 2000ms."
            )

        ticket = self.cb.admit()
        if ticket is None:
            logger.warning(
                "⚠️ Circuit Breaker %s. Fast failing OPA check -> DENY.",
                self.cb.state.value,
            )
            return "DENY"

        outcome = CallOutcome.INCONCLUSIVE
        try:
            decision, outcome = await self._query_opa(input_data)
            return decision
        except Exception:
            # _query_opa denies every failure it anticipates; anything else is
            # a local bug, and PolicyClient promises an erroring policy engine
            # yields DENY.
            logger.exception("🔥 OPA FAILURE (UNEXPECTED_ERROR); denying.")
            return "DENY"
        finally:
            self.cb.record(ticket, outcome)

    async def _query_opa(self, input_data: dict[str, Any]) -> tuple[str, CallOutcome]:
        """One OPA round trip: the decision and what it showed about OPA."""
        normalized_input = _normalize_opa_input(input_data)
        serialized_input = json.dumps(normalized_input)
        with tracer.start_as_current_span("governance.opa_check") as span:
            span.set_attribute(OBSERVATION_TYPE, "span")
            span.set_attribute(OBSERVATION_NAME, "opa_policy_check")
            span.set_attribute(OBSERVATION_INPUT, serialized_input)
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
                len(serialized_input),
            )

            headers = {}
            if self.auth_token:
                headers["Authorization"] = f"Bearer {self.auth_token}"

            # IMPORTANT: Do NOT use ?explain=full in the hot governance path.
            # explain=full forces OPA to serialize its full policy evaluation
            # trace (~100KB-1MB JSON), adding 13-17s of latency vs ~30ms without it.
            # The audit trail is captured via OTel span attributes above.
            # Use ?explain=notes for lightweight rule annotations if needed.
            #
            # Explain-mode logging is async and non-blocking — the hot path is
            # never delayed by explain requests.  See _explain_worker() and
            # start_explain_worker() for the background explain architecture.
            try:
                # HIGH-7 fix: use the pooled client — no new client per request.
                # The client's own timeouts apply (connect 2 s, read and write
                # 5 s, pool 2 s), so a saturated pool fails fast.
                response = await self._get_client().post(
                    self.target_url,
                    json={"input": normalized_input},
                    headers=headers,
                )
            except httpx.PoolTimeout as exc:
                # Every pooled connection is busy. This request is denied, but
                # that is no evidence OPA is down: if OPA is slow enough to
                # matter, the in-flight calls time out and trip the breaker.
                return _deny(
                    span, exc, "LOCAL_POOL_SATURATED"
                ), CallOutcome.INCONCLUSIVE
            except (httpx.UnsupportedProtocol, httpx.LocalProtocolError) as exc:
                # Raised before any byte reaches OPA: an unusable OPA_URL, or
                # an illegal header value such as a token with a newline.
                return _deny(
                    span, exc, "LOCAL_MISCONFIGURATION"
                ), CallOutcome.INCONCLUSIVE
            except httpx.TransportError as exc:
                return _deny(span, exc, "SYSTEM_FAILURE"), CallOutcome.UPSTREAM_FAILURE
            except Exception as exc:
                # Misconfiguration (e.g. a malformed OPA_URL) or a local bug.
                return _deny(span, exc, "SYSTEM_FAILURE"), CallOutcome.INCONCLUSIVE

            span.set_attribute(
                TRACE_METADATA_LATENCY_CURRENCY_TAX, (time.time() - start_time) * 1000
            )
            status = response.status_code
            # 5xx, or 408/429 from a proxy in front of OPA: no answer came back.
            if status >= 500 or status in (408, 429):
                return (
                    _deny(span, f"OPA returned HTTP {status}", "SYSTEM_FAILURE"),
                    CallOutcome.UPSTREAM_FAILURE,
                )
            if not 200 <= status < 300:
                return (
                    _deny(
                        span, f"OPA rejected the query: HTTP {status}", "OPA_REJECTED"
                    ),
                    CallOutcome.HEALTHY,
                )
            try:
                resp_json = response.json()
            except ValueError as exc:
                return _deny(span, exc, "MALFORMED_RESPONSE"), CallOutcome.HEALTHY
            if not isinstance(resp_json, dict):
                return (
                    _deny(
                        span, "OPA response is not a JSON object", "MALFORMED_RESPONSE"
                    ),
                    CallOutcome.HEALTHY,
                )

            decision_str = _decision_string(resp_json.get("result", "DENY"))
            span.set_attribute(TRACE_METADATA_GOVERNANCE_DECISION, decision_str)

            # The explanation is logged for the Auditor via the OTel span above.
            explanation = resp_json.get("explanation", [])
            logger.debug(
                "OPA explanation entries: %d",
                len(explanation) if isinstance(explanation, list) else 0,
            )

            # ── Async explain-mode logging (non-blocking) ────────────────
            # If CAGE_OPA_EXPLAIN_LOGGING is enabled, enqueue the policy
            # path, input, and decision for background explain=full fetching.
            # put_nowait() is used so the hot path is never blocked; if the
            # queue is full, the explain request is dropped.
            if CAGE_OPA_EXPLAIN_LOGGING:
                policy_path = input_data.get("action", "unknown")
                try:
                    _explain_queue.put_nowait(
                        (policy_path, normalized_input, decision_str)
                    )
                except asyncio.QueueFull:
                    logger.warning(
                        "OPA explain queue full (maxsize=%d) — dropping explain "
                        "request for policy=%s decision=%s.",
                        _explain_queue.maxsize,
                        policy_path,
                        decision_str,
                    )

            return decision_str, CallOutcome.HEALTHY
