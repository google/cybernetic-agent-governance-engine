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

"""Gateway pre-execution guard for advisor tool-executor nodes.

The advisor is an untrusted, zero-identity client of the CAGE gateway
(POAM-2026-080): it holds no governor, no signer and no routing-seal secret.
Every tool call a subgraph wants to run is therefore submitted to the
gateway's ``POST /governance/validate-action`` endpoint through the advisor's
standard :class:`GatewayClient` before the wrapped node may execute it. The
gateway authenticates this caller by its mesh workload identity, not by any
secret the advisor holds.

``validate-action`` only routes: it commits nothing and mints no seal. The
committing run happens in the gateway when the governed tool executes, so an
ALLOW here is advice, never authority.

Fail-closed contract, per batch:

* every call ``ALLOW`` or ``NARROW`` → the wrapped node runs the batch;
* in a graph with an approval path, a single-call batch answered
  ``REQUIRE_APPROVAL`` with a ``deferred_id`` →
  no tool runs; ``governance_status`` becomes ``REQUIRE_APPROVAL`` and the
  ``deferred_id`` is stored so the graph can pause for a human;
* a refusal (403 / DENY), DEFER, an unknown verdict, a
  ``REQUIRE_APPROVAL`` without a ``deferred_id``, an HTTP error, a timeout or
  an unreachable gateway → the whole batch is refused.

Once a human has approved (``approval_decision.approved`` and a
``deferred_id`` in state), the guard does not re-ask ``validate-action``: it
forwards the ``deferred_id`` in each tool call's arguments and the gateway
consumes that approval exactly once, re-validating the fresh params. The
advisor never decides that an approval holds.

Every refused call is answered with a ``ToolMessage`` so the conversation
stays well-formed.
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from langchain_core.messages import AIMessage, ToolMessage

from src.gateway.governance.decisions import GovernanceDecision
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient

logger = logging.getLogger(__name__)


class NodeFn(Protocol):
    """A LangGraph node: called with the graph state (by name), returns an update."""

    def __call__(self, state: Any) -> Awaitable[dict[str, Any]]: ...


GOVERNANCE_ALLOWED = "ALLOWED"
GOVERNANCE_DENIED = "DENIED"
GOVERNANCE_REQUIRE_APPROVAL = GovernanceDecision.REQUIRE_APPROVAL.value

#: Verdicts under which the wrapped node may execute the batch.
_EXECUTABLE_VERDICTS = frozenset({GovernanceDecision.ALLOW, GovernanceDecision.NARROW})


async def authorize_action(
    action: str, params: dict[str, Any]
) -> tuple[dict[str, Any] | None, str | None]:
    """Ask the gateway how one action must be routed.

    Returns:
        ``(result, None)`` when the gateway answered ``ALLOW``/``NARROW``, or
        ``REQUIRE_APPROVAL`` with a ``deferred_id``; otherwise
        ``(None, reason)``. Never raises: every failure mode is reported as a
        refusal reason so callers cannot fail open by accident.
    """
    try:
        result = await GatewayClient().validate_action(action=action, params=params)
    except Exception as exc:  # refusal (PermissionError), HTTP error, timeout: refuse
        return None, f"{type(exc).__name__}: {exc}"
    verdict = result.get("verdict") if isinstance(result, dict) else None
    if verdict in _EXECUTABLE_VERDICTS:
        return result, None
    if verdict == GovernanceDecision.REQUIRE_APPROVAL:
        if result.get("deferred_id"):
            return result, None
        return None, "gateway requires approval but parked no deferred_id"
    return None, f"gateway returned verdict {verdict!r}, not ALLOW or NARROW"


def _pending_tool_calls(state: Any) -> list[dict[str, Any]]:
    messages = state.get("messages") or []
    if not messages:
        return []
    return list(getattr(messages[-1], "tool_calls", None) or [])


def _approved_deferred_id(state: Any) -> str | None:
    decision = state.get("approval_decision") or {}
    deferred_id = state.get("deferred_id")
    if deferred_id and isinstance(decision, dict) and decision.get("approved") is True:
        return str(deferred_id)
    return None


def _answer_all(
    tool_calls: list[dict[str, Any]], reasons: dict[str, str], default: str
) -> list[ToolMessage]:
    return [
        ToolMessage(
            content=reasons.get(str(call.get("id")), default),
            tool_call_id=call.get("id"),
            name=call.get("name"),
        )
        for call in tool_calls
    ]


def _with_deferred_id(state: Any, deferred_id: str) -> Any:
    """Return ``state`` whose last message's tool calls carry ``deferred_id``."""
    messages = list(state.get("messages") or [])
    last = messages[-1]
    calls = [
        {**call, "args": {**(call.get("args") or {}), "deferred_id": deferred_id}}
        for call in (getattr(last, "tool_calls", None) or [])
    ]
    messages[-1] = AIMessage(content=getattr(last, "content", ""), tool_calls=calls)
    return {**state, "messages": messages}


def gateway_tool_guard(
    action: str, *, approvable: bool = False
) -> Callable[[NodeFn], NodeFn]:
    """Wrap a tool-executor node so it runs only as the gateway routes it.

    Args:
        action: Governance action name submitted to the gateway for every tool
            call in the batch (e.g. ``"execute_trade"``).
        approvable: Whether the wrapping graph has a human-approval path. When
            False, ``REQUIRE_APPROVAL`` refuses the batch like any other
            non-executable verdict.
    """

    def decorator(func: NodeFn) -> NodeFn:
        @functools.wraps(func)
        async def wrapper(state: Any) -> dict[str, Any]:
            tool_calls = _pending_tool_calls(state)
            if not tool_calls:
                return {"messages": []}

            approved_id = _approved_deferred_id(state) if approvable else None
            if approved_id is not None and len(tool_calls) > 1:
                return {
                    "messages": _answer_all(
                        tool_calls,
                        {},
                        "Governance refused this action: an approval covers exactly one call",
                    ),
                    "governance_status": GOVERNANCE_DENIED,
                    "governance_envelope": None,
                    "deferred_id": None,
                    "approval_decision": None,
                }
            if approved_id is not None:
                # The gateway, not the advisor, decides whether the approval
                # covers these params; the id is single-use on both sides.
                result = await func(_with_deferred_id(state, approved_id))
                return {
                    **result,
                    "governance_status": GOVERNANCE_ALLOWED,
                    "governance_envelope": None,
                    "deferred_id": None,
                    "approval_decision": None,
                }

            verdicts: list[dict[str, Any]] = []
            refusals: dict[str, str] = {}
            deferred_ids: dict[str, str] = {}

            for call in tool_calls:
                args = call.get("args") or {}
                params: dict[str, Any] = {
                    **(args if isinstance(args, dict) else {}),
                    "tool_name": call.get("name", ""),
                }
                params.pop("deferred_id", None)  # never self-asserted by the model
                params.setdefault("action", action)
                verdict, reason = await authorize_action(action, params)
                if verdict is None:
                    refusals[str(call.get("id"))] = reason or "refused"
                elif verdict.get("verdict") == GovernanceDecision.REQUIRE_APPROVAL:
                    if not approvable:
                        refusals[str(call.get("id"))] = (
                            "gateway requires human approval"
                        )
                        continue
                    deferred_ids[str(call.get("id"))] = str(verdict["deferred_id"])
                else:
                    verdicts.append(verdict)

            if deferred_ids and len(tool_calls) > 1:
                # An approval binds one call's params; batching it with others
                # would forward the deferred_id to calls it does not cover.
                for call_id in deferred_ids:
                    refusals.setdefault(
                        call_id, "a call that requires approval must be submitted alone"
                    )
            if refusals:
                logger.warning(
                    "Gateway refused %s for %d of %d tool call(s) — batch not executed: %s",
                    action,
                    len(refusals),
                    len(tool_calls),
                    refusals,
                )
                return {
                    "messages": _answer_all(
                        tool_calls,
                        {
                            k: f"Governance refused this action: {v}"
                            for k, v in refusals.items()
                        },
                        "Governance refused this action: another tool call in the same batch was refused",
                    ),
                    "governance_status": GOVERNANCE_DENIED,
                    "governance_envelope": None,
                }

            if deferred_ids:
                (deferred_id,) = deferred_ids.values()
                logger.info(
                    "Gateway requires approval for %s — batch parked as deferred_id=%s",
                    action,
                    deferred_id,
                )
                return {
                    "messages": _answer_all(
                        tool_calls,
                        {},
                        f"Awaiting human approval (deferred_id={deferred_id}); not executed.",
                    ),
                    "governance_status": GOVERNANCE_REQUIRE_APPROVAL,
                    "governance_envelope": None,
                    "deferred_id": deferred_id,
                }

            result = await func(state)
            return {
                **result,
                "governance_status": GOVERNANCE_ALLOWED,
                "governance_envelope": verdicts[-1] if verdicts else None,
            }

        return wrapper

    return decorator
