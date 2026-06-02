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
OTel-compliant replacements for the former Langfuse SDK helpers.

All Langfuse interactions are now routed exclusively via:
  - Prompt fetch  → compliance-bridge HTTP proxy  (GET /v1/prompts/:name)
  - Compliance scoring → OTel span events         (picked up by compliance-bridge)

The compliance-bridge is the SOLE authorised Langfuse SDK consumer.
"""

import os
import json
import logging
from typing import Literal, Optional, Dict, Any

import httpx
import opentelemetry.trace
from src.compliance_bridge.types import ISO_CONTROL_MAP  # noqa: F401

logger = logging.getLogger(__name__)

# ISO_CONTROL_MAP imported from src.compliance_bridge.types

IsoOutcome = Literal["PASSED", "BLOCKED", "ESCALATED", "SKIPPED"]

# ---------------------------------------------------------------------------
# Prompt management — via compliance-bridge HTTP proxy
# ---------------------------------------------------------------------------

def get_managed_prompt(
    name: str,
    fallback: str = "",
    label: str = "production",
) -> str:
    """
    Fetches a prompt from the compliance-bridge prompt proxy.

    GET {COMPLIANCE_BRIDGE_URL}/v1/prompts/{name}?label={label}

    On HTTP 200 returns response.json()["text"].
    On 404 or any network/timeout error, logs a warning and returns ``fallback``.

    Args:
        name:     Prompt name registered in Langfuse (e.g. 'agent/explainer')
        fallback: Static text to return when the bridge is unreachable
        label:    Langfuse prompt label (default: 'production')
    """
    bridge_url = os.environ.get("COMPLIANCE_BRIDGE_URL", "http://compliance-bridge:3001")
    url = f"{bridge_url}/v1/prompts/{name}"
    try:
        response = httpx.get(url, params={"label": label}, timeout=5.0)
        if response.status_code == 200:
            text = response.json()["text"]
            logger.info(f"[prompts] fetched {name}@{label}")
            return text
        logger.warning(
            f"[prompts] bridge returned HTTP {response.status_code} for "
            f"'{name}@{label}'; using fallback."
        )
    except Exception as exc:
        logger.warning(
            f"[prompts] failed to fetch '{name}@{label}' from bridge "
            f"({bridge_url}): {exc}; using fallback."
        )
    return fallback


# ---------------------------------------------------------------------------
# ISO 42001 evidence tagging helpers — via OTel spans
# ---------------------------------------------------------------------------

def trace_with_iso_control(
    name: str,
    control_id: str,
    outcome: IsoOutcome,
    metadata: Optional[Dict[str, Any]] = None,
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
            "langfuse.trace.tags",
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
    them into Langfuse scores so that the time-windowed safety_rate per
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
    "COMPLETED":       "PASSED",
    "ROLLED_BACK":     "BLOCKED",    # Rollback succeeded — governance intervened
    "PARTIAL_FAILURE": "ESCALATED",  # Rollback failed — human review needed
    "PENDING":         "SKIPPED",    # WAL intent only — not yet executed
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
        control_id = ISO_CONTROL_MAP.get("saga_rollback", "A.8.4")

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
            node_name, uca_ref, status, outcome,
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

        control_id = ISO_CONTROL_MAP.get("saga_rollback", "A.8.4")
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
            node_name, error,
        )

