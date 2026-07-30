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
create_ftra_node() — LangGraph node factory for the FTRA Tier 0.5 gate.

Placement in the graph
-----------------------
The FTRA node is inserted between ``evaluator`` and ``safety_check``:

    evaluator → ftra_node → safety_check   (CLEAR)
                          → explainer       (BLOCKED)
                          → [parked]        (HITL_REQUIRED — DeferQueue db=1)

The node reads ``execution_plan_output`` and ``evaluation_result`` from
``AgentState``, runs :class:`PlanGraphAnalyzer`, and writes back:

    ftra_status   — "CLEAR" | "HITL_REQUIRED" | "BLOCKED"
    ftra_result   — serialised :class:`ReachabilityResult` dict
    ftra_defer_id — DeferQueue token ID when verdict is HITL_REQUIRED

Routing
-------
``route_after_ftra()`` (also exported from this module) is the conditional
edge function that reads ``ftra_status`` and returns the next node name.
It is registered in ``graph.py`` via::

    workflow.add_conditional_edges("ftra_node", route_after_ftra)

OTel spans
----------
Every analysis emits a ``cage.ftra_analysis`` span with attributes:

    cage.ftra.plan_id
    cage.ftra.verdict
    cage.ftra.worst_case_classification
    cage.ftra.reachable_terminal_count
    cage.ftra.confidence_at_analysis
    cage.ftra.ctrl_id  → "CTRL_FTRA_001"

Usage (graph.py)::

    from src.gateway.governance.ftra.node_factory import create_ftra_node, route_after_ftra

    ftra_node_fn = create_ftra_node()
    workflow.add_node("ftra_node", ftra_node_fn)
    workflow.add_conditional_edges("ftra_node", route_after_ftra)
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("Gateway.Governance.FTRA.NodeFactory")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CTRL_FTRA_001 = "CTRL_FTRA_001"

# ---------------------------------------------------------------------------
# route_after_ftra — conditional edge function
# ---------------------------------------------------------------------------


def route_after_ftra(state: dict[str, Any]) -> str:
    """Conditional edge: read ``ftra_status`` and return the next node name.

    Routing table:
        CLEAR         → "safety_check"
        HITL_REQUIRED → "ftra_hitl_park"  (handled inside the node; this
                         branch should not be reached in normal flow because
                         the node raises ``NodeInterrupt`` for HITL parking)
        BLOCKED       → "explainer"
        <missing>     → "explainer"  (fail-closed)
    """
    status = state.get("ftra_status", "BLOCKED")
    if status == "CLEAR":
        return "safety_check"
    if status == "HITL_REQUIRED":
        # The node raises NodeInterrupt before returning state for HITL_REQUIRED,
        # so this branch is a safety fallback only.
        return "explainer"
    # BLOCKED or unknown
    return "explainer"


# ---------------------------------------------------------------------------
# create_ftra_node — node factory
# ---------------------------------------------------------------------------


def create_ftra_node(
    registry_path: Any | None = None,
) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Return a LangGraph node function that performs FTRA analysis.

    Args:
        registry_path: Optional :class:`pathlib.Path` override for the
                       terminal registry JSON.  Defaults to the compiled
                       ``config/ftra/terminal_registry.json``.

    Returns:
        An async-compatible node function ``ftra_node(state) -> state_patch``.
    """
    from src.gateway.governance.ftra.classifier import IrreversibilityClassifier
    from src.gateway.governance.ftra.graph_analyzer import PlanGraphAnalyzer
    from src.gateway.governance.ftra.models import FTRAVerdict

    classifier = IrreversibilityClassifier(registry_path=registry_path)
    analyzer = PlanGraphAnalyzer(classifier=classifier)

    def ftra_node(state: dict[str, Any]) -> dict[str, Any]:
        """FTRA Tier 0.5 governance gate — commencement-time reachability check.

        Reads:
            execution_plan_output  — raw plan dict or JSON string from execution_analyst
            evaluation_result      — Evaluator verdict dict (must contain ``confidence``)

        Writes:
            ftra_status    — "CLEAR" | "HITL_REQUIRED" | "BLOCKED"
            ftra_result    — serialised ReachabilityResult dict
            ftra_defer_id  — DeferQueue token ID (HITL_REQUIRED only)
        """
        try:
            return _run_ftra(state, analyzer)
        except Exception as exc:
            # CRITICAL: NodeInterrupt (and its parent GraphInterrupt) are
            # subclasses of Exception in LangGraph — they are the mechanism
            # by which _raise_node_interrupt() suspends the thread for HITL
            # review. They must propagate to the LangGraph runtime, not be
            # swallowed here. A prior version of this handler caught them
            # unconditionally, silently converting every HITL_REQUIRED
            # verdict into a fail-closed BLOCKED response and defeating the
            # DeferQueue human-in-the-loop pathway entirely.
            try:
                from langgraph.errors import GraphInterrupt

                if isinstance(exc, GraphInterrupt):
                    raise
            except ImportError:
                pass
            logger.error(
                "FTRA node: unhandled exception (%s) — failing closed (BLOCKED).", exc
            )
            return {
                "ftra_status": "BLOCKED",
                "ftra_result": {
                    "error": str(exc),
                    "verdict": "BLOCKED",
                    "ctrl_id": _CTRL_FTRA_001,
                },
                "ftra_defer_id": None,
            }

    return ftra_node


# ---------------------------------------------------------------------------
# Internal implementation
# ---------------------------------------------------------------------------


def _run_ftra(state: dict[str, Any], analyzer: Any) -> dict[str, Any]:
    """Core FTRA logic — may raise; caller wraps in try/except."""
    from opentelemetry import trace

    from src.gateway.governance.ftra.models import FTRAVerdict

    tracer = trace.get_tracer("cage.ftra")

    # ----------------------------------------------------------------
    # 1. Extract execution plan
    # ----------------------------------------------------------------
    raw_plan = state.get("execution_plan_output")
    if raw_plan is None:
        logger.warning(
            "FTRA node: execution_plan_output is None — failing closed (BLOCKED)."
        )
        return {
            "ftra_status": "BLOCKED",
            "ftra_result": {
                "error": "execution_plan_output missing from state",
                "verdict": "BLOCKED",
                "ctrl_id": _CTRL_FTRA_001,
            },
            "ftra_defer_id": None,
        }

    plan = _parse_plan(raw_plan)
    if plan is None:
        logger.warning(
            "FTRA node: could not parse execution_plan_output — failing closed."
        )
        return {
            "ftra_status": "BLOCKED",
            "ftra_result": {
                "error": "execution_plan_output could not be parsed as ExecutionPlan",
                "verdict": "BLOCKED",
                "ctrl_id": _CTRL_FTRA_001,
            },
            "ftra_defer_id": None,
        }

    # ----------------------------------------------------------------
    # 2. Extract evaluator confidence
    # ----------------------------------------------------------------
    evaluation_result: dict[str, Any] = state.get("evaluation_result") or {}
    confidence: float = float(evaluation_result.get("confidence", 0.0))

    # ----------------------------------------------------------------
    # 3. Run reachability analysis inside OTel span
    # ----------------------------------------------------------------
    with tracer.start_as_current_span("cage.ftra_analysis") as span:
        span.set_attribute("cage.ftra.ctrl_id", _CTRL_FTRA_001)
        span.set_attribute("cage.ftra.plan_id", plan.plan_id)
        span.set_attribute("cage.ftra.confidence_at_analysis", confidence)

        result = analyzer.analyze(plan, confidence)

        span.set_attribute("cage.ftra.verdict", result.verdict.value)
        span.set_attribute(
            "cage.ftra.worst_case_classification",
            result.worst_case_classification.value,
        )
        span.set_attribute(
            "cage.ftra.reachable_terminal_count", len(result.reachable_terminals)
        )
        span.set_attribute("cage.ftra.total_steps", result.total_steps)
        span.set_attribute(
            "cage.ftra.reachable_step_count", result.reachable_step_count
        )

    # ----------------------------------------------------------------
    # 4. Build state patch
    # ----------------------------------------------------------------
    result_dict = result.model_dump()
    result_dict["ctrl_id"] = _CTRL_FTRA_001

    if result.verdict == FTRAVerdict.CLEAR:
        logger.info("FTRA: plan '%s' CLEAR — proceeding to safety_check.", plan.plan_id)
        return {
            "ftra_status": "CLEAR",
            "ftra_result": result_dict,
            "ftra_defer_id": None,
        }

    if result.verdict == FTRAVerdict.HITL_REQUIRED:
        defer_id = _park_in_defer_queue(state, result_dict, confidence)
        logger.warning(
            "FTRA: plan '%s' HITL_REQUIRED — parked as defer_id='%s'.",
            plan.plan_id,
            defer_id,
        )
        # Raise NodeInterrupt so LangGraph suspends the thread.
        # The graph will resume when the human clears the defer token.
        _raise_node_interrupt(defer_id, result_dict)
        # Fallback (NodeInterrupt not available in this LangGraph version):
        return {
            "ftra_status": "HITL_REQUIRED",
            "ftra_result": result_dict,
            "ftra_defer_id": defer_id,
        }

    # BLOCKED
    logger.warning(
        "FTRA: plan '%s' BLOCKED (confidence=%.3f < %.2f, irreversible terminals=%s).",
        plan.plan_id,
        confidence,
        0.70,
        result.reachable_terminals,
    )
    return {
        "ftra_status": "BLOCKED",
        "ftra_result": result_dict,
        "ftra_defer_id": None,
    }


def _parse_plan(raw: Any) -> Any | None:
    """Parse raw execution_plan_output into an ExecutionPlan.

    Accepts:
        - An already-parsed ExecutionPlan object
        - A dict (from JSON-decoded state)
        - A JSON string
    """
    from src.governed_financial_advisor.agents.execution_analyst.agent import (
        ExecutionPlan,
    )

    if isinstance(raw, ExecutionPlan):
        return raw
    if isinstance(raw, dict):
        try:
            return ExecutionPlan.model_validate(raw)
        except Exception as exc:
            logger.warning("FTRA: dict→ExecutionPlan validation failed: %s", exc)
            return None
    if isinstance(raw, str):
        try:
            return ExecutionPlan.model_validate_json(raw)
        except Exception:
            pass
        # Try stripping markdown code fences
        try:
            import re

            cleaned = re.sub(r"```[a-z]*\n?", "", raw).strip()
            return ExecutionPlan.model_validate_json(cleaned)
        except Exception as exc:
            logger.warning("FTRA: str→ExecutionPlan parse failed: %s", exc)
            return None
    logger.warning("FTRA: unexpected execution_plan_output type: %s", type(raw))
    return None


def _park_in_defer_queue(
    state: dict[str, Any],
    result_dict: dict[str, Any],
    confidence: float,
) -> str:
    """Park the suspended plan in DeferQueue db=1 and return the defer_id.

    Connects to Redis db=1 via REDIS_URL (matching the deployment contract
    documented in defer_queue.py — the DEFER token store is isolated from the
    LangGraph checkpointer at db=0) and parks the token through the existing
    DeferQueue infrastructure. Falls back to a local, unpersisted UUID token
    if Redis is unavailable — the HITL_REQUIRED verdict is still enforced by
    the graph interrupt/state routing, but external HITL API resolution
    (POST /v1/defer/{id}/escalate or /inject) will not find this token in
    that fallback case, since it was never written to Redis.

    NOTE (fixed): a prior version instantiated DeferQueue() with zero
    arguments, but DeferQueue.__init__ requires a redis_client. That always
    raised TypeError, which was silently caught by the except-Exception
    fallback below — meaning every HITL_REQUIRED verdict previously fell
    through to the unpersisted-token path unconditionally. See
    src/compliance_bridge/main.py's list_defer_pending()/resolve endpoints
    for the correct DeferQueue(client) instantiation pattern this mirrors.
    """
    import asyncio
    import os

    from src.gateway.governance.defer_queue import DeferQueue, DeferReason, DeferToken

    thread_id: str = state.get("thread_id", str(uuid.uuid4()))
    token = DeferToken(
        thread_id=thread_id,
        defer_reason=DeferReason.FTRA_IRREVERSIBLE_TERMINAL,
        opa_input_snapshot={
            "ftra_result": result_dict,
            "plan_id": result_dict.get("plan_id", ""),
        },
        confidence_score=confidence,
        aarm_vector="AARM-V9",  # Forward-looking reachability block
    )

    async def _park() -> str:
        import redis.asyncio as aioredis

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        client = aioredis.from_url(redis_url, db=1, decode_responses=True)
        try:
            queue = DeferQueue(client)
            return await queue.park(token)
        finally:
            await client.aclose()

    try:
        # Run in a new event loop if we're not already in one
        try:
            asyncio.get_running_loop()
            # We're inside an async context — schedule as a task
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, _park())
                return future.result(timeout=5.0)
        except RuntimeError:
            # No running loop — safe to use asyncio.run
            return asyncio.run(_park())
    except Exception as exc:
        logger.error(
            "FTRA: DeferQueue park failed (%s) — using local defer_id only "
            "(token NOT persisted to Redis; HITL API will not find it).",
            exc,
        )
        return token.defer_id


def _raise_node_interrupt(defer_id: str, result_dict: dict[str, Any]) -> None:
    """Raise a LangGraph NodeInterrupt to suspend the thread for HITL review.

    Gracefully degrades if NodeInterrupt is not available in the installed
    LangGraph version — the HITL_REQUIRED state patch still routes correctly
    via ``route_after_ftra``.
    """
    try:
        from langgraph.errors import NodeInterrupt

        raise NodeInterrupt(
            {
                "reason": "FTRA_IRREVERSIBLE_TERMINAL",
                "defer_id": defer_id,
                "ctrl_id": _CTRL_FTRA_001,
                "ftra_result": result_dict,
            }
        )
    except ImportError:
        logger.warning(
            "FTRA: NodeInterrupt not available in this LangGraph version — "
            "HITL_REQUIRED will be enforced via route_after_ftra state routing only."
        )
