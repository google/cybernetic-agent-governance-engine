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

Fail-closed contract: a tool batch executes only if the gateway returns an
explicit ``APPROVED`` verdict for **every** tool call in it. A DENIED verdict,
a DEFER/PAUSE verdict, a missing verdict, an HTTP error, a timeout or an
unreachable gateway all refuse the whole batch — no tool runs, and each tool
call is answered with a refusal ``ToolMessage`` so the conversation stays
well-formed.
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from langchain_core.messages import ToolMessage

from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient

logger = logging.getLogger(__name__)

NodeFn = Callable[[Any], Awaitable[dict[str, Any]]]

GOVERNANCE_ALLOWED = "ALLOWED"
GOVERNANCE_DENIED = "DENIED"


async def authorize_action(
    action: str, params: dict[str, Any]
) -> tuple[dict[str, Any] | None, str | None]:
    """Ask the gateway to validate one action.

    Returns:
        ``(verdict, None)`` when the gateway explicitly APPROVED the action,
        otherwise ``(None, reason)``. Never raises: every failure mode is
        reported as a refusal reason so callers cannot fail open by accident.
    """
    try:
        result = await GatewayClient().validate_action(action=action, params=params)
    except Exception as exc:  # DENIED (PermissionError), HTTP error, timeout: refuse
        return None, f"{type(exc).__name__}: {exc}"
    verdict = result.get("verdict") if isinstance(result, dict) else None
    if verdict != "APPROVED":
        return None, f"gateway returned verdict {verdict!r}, not APPROVED"
    return result, None


def _pending_tool_calls(state: Any) -> list[dict[str, Any]]:
    messages = state.get("messages") or []
    if not messages:
        return []
    return list(getattr(messages[-1], "tool_calls", None) or [])


def gateway_tool_guard(action: str) -> Callable[[NodeFn], NodeFn]:
    """Wrap a tool-executor node so it runs only after gateway approval.

    Args:
        action: Governance action name submitted to the gateway for every tool
            call in the batch (e.g. ``"execute_trade"``).
    """

    def decorator(func: NodeFn) -> NodeFn:
        @functools.wraps(func)
        async def wrapper(state: Any) -> dict[str, Any]:
            tool_calls = _pending_tool_calls(state)
            if not tool_calls:
                return {"messages": []}
            verdicts: list[dict[str, Any]] = []
            refusals: dict[str, str] = {}

            for call in tool_calls:
                args = call.get("args") or {}
                params: dict[str, Any] = {
                    **(args if isinstance(args, dict) else {}),
                    "tool_name": call.get("name", ""),
                }
                params.setdefault("action", action)
                verdict, reason = await authorize_action(action, params)
                if verdict is None:
                    refusals[str(call.get("id"))] = reason or "refused"
                else:
                    verdicts.append(verdict)

            if refusals:
                logger.warning(
                    "Gateway refused %s for %d of %d tool call(s) — batch not executed: %s",
                    action,
                    len(refusals),
                    len(tool_calls),
                    refusals,
                )
                return {
                    "messages": [
                        ToolMessage(
                            content=(
                                "Governance refused this action: "
                                + refusals.get(
                                    str(call.get("id")),
                                    "another tool call in the same batch was refused",
                                )
                            ),
                            tool_call_id=call.get("id"),
                            name=call.get("name"),
                        )
                        for call in tool_calls
                    ],
                    "governance_status": GOVERNANCE_DENIED,
                    "governance_envelope": None,
                }

            result = await func(state)
            return {
                **result,
                "governance_status": GOVERNANCE_ALLOWED,
                "governance_envelope": verdicts[-1] if verdicts else None,
            }

        return wrapper

    return decorator
