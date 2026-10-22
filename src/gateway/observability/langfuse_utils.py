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
OTel-compliant replacements for the former Telemetry SDK helpers.

All Telemetry interactions are now routed exclusively via:
  - Prompt fetch  → compliance-bridge HTTP proxy  (GET /v1/prompts/:name)
  - Compliance scoring → OTel span events         (picked up by compliance-bridge)

The compliance-bridge is the SOLE authorised Telemetry SDK consumer.
"""

import asyncio
import json
import logging
import os
import threading
from typing import Any, Literal

import httpx
import opentelemetry.trace

from src.gateway.governance.iso_control import get_iso_control_map
from src.gateway.observability.attributes import TRACE_TAGS

logger = logging.getLogger(__name__)

# Use region-aware get_iso_control_map(region) from src.gateway.governance.iso_control


def _get_iso_control_map() -> dict[str, str]:
    """Return the ISO control map for the current deployment region."""
    _region = os.environ.get("CAGE_DEPLOYMENT_REGION", "LOCAL")
    return get_iso_control_map(_region)


IsoOutcome = Literal["PASSED", "BLOCKED", "ESCALATED", "SKIPPED"]

# ---------------------------------------------------------------------------
# Prompt management — via compliance-bridge HTTP proxy & in-memory PromptRegistry
# ---------------------------------------------------------------------------

DEFAULT_PROMPT_NAMES: tuple[str, ...] = (
    "agent/explainer",
    "agent/execution_analyst",
    "agent/financial_coordinator",
    "agent/governed_trader",
)


class PromptRegistry:
    """In-memory prompt cache refreshed asynchronously over a pooled httpx client.

    Eliminates per-request synchronous ``httpx.get`` calls on the advisor hot
    path. Prompts are warmed on lifespan startup and refreshed periodically in
    the background (default every 300s). ``get()`` reads strictly from memory
    and falls back to the caller's static fallback prompt if a prompt has not
    been populated yet.
    """

    def __init__(self, refresh_interval_seconds: float = 300.0) -> None:
        self._refresh_interval_seconds = refresh_interval_seconds
        self._cache: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()
        self._client: httpx.AsyncClient | None = None
        self._task: asyncio.Task[None] | None = None
        self._stop_event: asyncio.Event | None = None

    def get(
        self,
        name: str,
        fallback: str = "",
        label: str = "production",
    ) -> str:
        """Return the cached prompt text from memory, or ``fallback`` on miss."""
        with self._lock:
            return self._cache.get((name, label), fallback)

    def set(
        self,
        name: str,
        text: str,
        label: str = "production",
    ) -> None:
        """Store a prompt in the in-memory cache."""
        with self._lock:
            self._cache[(name, label)] = text

    def clear(self) -> None:
        """Clear all cached prompts (used in tests)."""
        with self._lock:
            self._cache.clear()

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(connect=2.0, read=5.0, write=5.0, pool=2.0),
                limits=httpx.Limits(max_keepalive_connections=4, max_connections=8),
            )
        return self._client

    async def refresh_prompt(
        self,
        name: str,
        label: str = "production",
    ) -> str | None:
        """Fetch a single prompt from the compliance-bridge and update memory."""
        bridge_url = os.environ.get(
            "COMPLIANCE_BRIDGE_URL", "http://compliance-bridge:3001"
        )
        url = f"{bridge_url}/v1/prompts/{name}"
        client = self._ensure_client()
        try:
            response = await client.get(url, params={"label": label})
            if response.status_code == 200:
                text = response.json()["text"]
                self.set(name, text, label=label)
                logger.info(
                    "[prompts] refreshed %s@%s into PromptRegistry", name, label
                )
                return text
            logger.debug(
                "[prompts] bridge returned HTTP %s for '%s@%s'; keeping cached/fallback.",
                response.status_code,
                name,
                label,
            )
        except Exception as exc:
            logger.debug(
                "[prompts] failed to refresh '%s@%s' from bridge (%s): %s; keeping cached/fallback.",
                name,
                label,
                bridge_url,
                exc,
            )
        return None

    async def refresh_all(
        self,
        names: tuple[str, ...] = DEFAULT_PROMPT_NAMES,
        label: str = "production",
    ) -> None:
        """Concurrently refresh all managed prompts from the compliance-bridge."""
        await asyncio.gather(
            *(self.refresh_prompt(name, label=label) for name in names),
            return_exceptions=True,
        )

    async def _refresh_loop(
        self,
        names: tuple[str, ...],
        label: str,
    ) -> None:
        if self._stop_event is None:
            return
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self._refresh_interval_seconds,
                )
                break
            except TimeoutError:
                await self.refresh_all(names=names, label=label)
            except asyncio.CancelledError:
                break

    async def start(
        self,
        names: tuple[str, ...] = DEFAULT_PROMPT_NAMES,
        label: str = "production",
    ) -> None:
        """Warm the prompt cache and start the periodic background refresh loop."""
        await self.refresh_all(names=names, label=label)
        if self._task is None or self._task.done():
            self._stop_event = asyncio.Event()
            self._task = asyncio.create_task(
                self._refresh_loop(names=names, label=label),
                name="cage-prompt-registry-refresh",
            )

    async def stop(self) -> None:
        """Stop the background refresh task and close the pooled HTTP client."""
        if self._stop_event is not None:
            self._stop_event.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None


_prompt_registry = PromptRegistry(
    refresh_interval_seconds=float(
        os.environ.get("PROMPT_REGISTRY_REFRESH_SECONDS", "300.0")
    )
)


def get_prompt_registry() -> PromptRegistry:
    """Return the process-wide PromptRegistry singleton."""
    return _prompt_registry


def get_managed_prompt(
    name: str,
    fallback: str = "",
    label: str = "production",
) -> str:
    """Return a managed prompt from the in-memory ``PromptRegistry``.

    Never performs synchronous HTTP I/O on the calling thread or event loop.
    Returns the cached prompt populated by ``PromptRegistry`` (or ``fallback``
    if the prompt has not been warmed or the compliance-bridge was unreachable).

    Args:
        name:     Prompt name registered in Telemetry (e.g. 'agent/explainer')
        fallback: Static text to return when the prompt is not in memory
        label:    Telemetry prompt label (default: 'production')
    """
    return _prompt_registry.get(name, fallback=fallback, label=label)


# ---------------------------------------------------------------------------
# ISO 42001 evidence tagging helpers — via OTel spans
# ---------------------------------------------------------------------------


def trace_with_iso_control(
    name: str,
    control_id: str,
    outcome: IsoOutcome,
    metadata: dict[str, Any] | None = None,
) -> None:
    """
    Records an ISO 42001 governance event as an OTel span.

    The compliance-bridge picks up the iso42001.* attributes from the OTLP
    stream and aggregates them into per-control safety_rate metrics.

    Args:
        name:       Span name, e.g. 'nemo-input-scan'
        control_id: ISO 42001 Annex A control, e.g. 'A.9.2'
        outcome:    'PASSED' | 'BLOCKED' | 'ESCALATED' | 'SKIPPED'
        metadata:   Optional extra key-value pairs serialised as JSON
    """
    tracer = opentelemetry.trace.get_tracer(__name__)
    with tracer.start_as_current_span(name) as span:
        span.set_attribute("iso42001.control_id", control_id)
        span.set_attribute("iso42001.outcome", outcome)
        span.set_attribute("iso42001.standard", "ISO/IEC 42001:2023")
        span.set_attribute(
            TRACE_TAGS,
            json.dumps(["iso-42001", f"control:{control_id}"]),
        )
        if metadata is not None:
            span.set_attribute("iso42001.metadata", json.dumps(metadata))


def score_compliance_event(
    trace_id: str,
    control_id: str,
    passed: bool,
    comment: str = "",
) -> None:
    """
    Emits a compliance score as an OTel span event on the current span.

    The compliance-bridge reads these events from the OTLP stream and converts
    them into Telemetry scores so that the time-windowed safety_rate per
    control ID remains accurate.

    Args:
        trace_id:   Logical trace identifier (forwarded as span attribute)
        control_id: ISO 42001 control ID, e.g. 'SC-4'
        passed:     True if the control check passed, False if it failed/blocked
        comment:    Optional human-readable justification
    """
    span = opentelemetry.trace.get_current_span()
    span.add_event(
        "compliance.score",
        attributes={
            "compliance.control_id": control_id,
            "compliance.passed": "1" if passed else "0",
            "compliance.score": "1.0" if passed else "0.0",
            "compliance.comment": comment,
            "compliance.trace_id": trace_id,
        },
    )
    span.set_attribute(
        f"iso42001.{control_id}.passed",
        1.0 if passed else 0.0,
    )


# ---------------------------------------------------------------------------
# SagaCallbackHandler — Phase 3.1 (on_node_end interceptor)
#
# Fires an OTel compliance span immediately when any Saga node finishes,
# without waiting for the terminal node.  This ensures that rollback
# evidence survives even if the graph crashes before reaching END.
#
# Usage — attach to any LangGraph node that wraps a Saga function:
#
#   graph.add_node(
#       "saga_router",
#       saga_router_node,
#       config={"callbacks": [SagaCallbackHandler()]},
#   )
#
# Or attach globally via the RunnableConfig:
#
#   graph.invoke(state, config={"callbacks": [SagaCallbackHandler()]})
# ---------------------------------------------------------------------------


# Node name prefixes that identify compiler-generated Saga nodes
_SAGA_NODE_PREFIXES = ("forward_", "compensate_", "saga_router")

# Map ledger status → ISO 42001 outcome for span tagging
_STATUS_TO_OUTCOME: dict[str, IsoOutcome] = {
    "COMPLETED": "PASSED",
    "ROLLED_BACK": "BLOCKED",  # Rollback succeeded — governance intervened
    "PARTIAL_FAILURE": "ESCALATED",  # Rollback failed — human review needed
    "PENDING": "SKIPPED",  # WAL intent only — not yet executed
}


class SagaCallbackHandler:
    """LangChain-compatible callback handler for Saga node telemetry.

    Emits an OTel compliance span on ``on_chain_end`` (i.e. node completion)
    for any compiler-generated Saga node.  Each span is tagged with:

    - ``iso42001.control_id``  → "A.8.4" (AI System Operation)
    - ``stpa.uca_ref``         → UCA ID from the ledger entry (e.g. "UCA-4")
    - ``stpa.node_name``       → The node function name
    - ``iso42001.outcome``     → PASSED | BLOCKED | ESCALATED | SKIPPED
    - ``saga.idempotency_key`` → Derived key used for the compensating call

    These spans are picked up by the compliance-bridge OTLP collector and
    aggregated into the per-control ``safety_rate`` metric used by Lula.
    """

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: object = None,
        parent_run_id: object = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """Fires immediately when a node returns, before the next node executes."""
        node_name: str = kwargs.get("name", "") or ""
        if not any(node_name.startswith(p) for p in _SAGA_NODE_PREFIXES):
            return  # not a Saga node — skip

        # Extract the most recent ledger entry from the node output to get UCA ref
        ledger_entries: list[dict] = outputs.get("completed_transactions", [])
        latest = ledger_entries[-1] if ledger_entries else {}

        uca_ref = latest.get("uca_ref", "unknown")
        status = latest.get("status", "PENDING")
        idempotency_key = latest.get("idempotency_key", "")
        outcome: IsoOutcome = _STATUS_TO_OUTCOME.get(status, "ESCALATED")
        control_id = _get_iso_control_map().get("saga_rollback", "A.8.4")

        trace_with_iso_control(
            name=f"saga_node.{node_name}",
            control_id=control_id,
            outcome=outcome,
            metadata={
                "stpa.uca_ref": uca_ref,
                "stpa.node_name": node_name,
                "stpa.ledger_status": status,
                "saga.idempotency_key": idempotency_key,
            },
        )
        logger.info(
            "SagaCallbackHandler: emitted span node=%s uca_ref=%s status=%s outcome=%s",
            node_name,
            uca_ref,
            status,
            outcome,
        )

    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: object = None,
        parent_run_id: object = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """Fires if a Saga node raises an unhandled exception."""
        node_name: str = kwargs.get("name", "") or ""
        if not any(node_name.startswith(p) for p in _SAGA_NODE_PREFIXES):
            return

        control_id = _get_iso_control_map().get("saga_rollback", "A.8.4")
        trace_with_iso_control(
            name=f"saga_node.{node_name}.error",
            control_id=control_id,
            outcome="ESCALATED",
            metadata={
                "stpa.node_name": node_name,
                "error.type": type(error).__name__,
                "error.message": str(error),
            },
        )
        logger.error(
            "SagaCallbackHandler: unhandled error in node=%s err=%s",
            node_name,
            error,
        )
