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
CAGE LangGraph Integration Adapter.

Provides the `@cage_guard` decorator that integrates CAGE governance into
LangGraph-based agent workflows. Intercepts LangGraph node execution and
submits proposed actions to the CAGE Gateway via `CageClient.validate_action()`
for pre-execution HTTP PEP mediation.

Note:
    `CageClient` performs HTTP status/verdict mediation and Pydantic schema
    validation only (`GovernanceEnvelope.signature` and `expires_at` are not
    verified client-side).
"""

import functools
import logging
from collections.abc import Callable
from typing import Any, TypeVar

from ..core import CageClient
from ..exceptions import (
    DeferralPending,
    PolicyViolationException,
)

logger = logging.getLogger("CageClient.LangGraphAdapter")

F = TypeVar("F", bound=Callable[..., Any])


def cage_guard(
    client: CageClient,
    action: str,
    agent_id_key: str = "agent_id",
) -> Callable[[F], F]:
    """
    Decorator that enforces CAGE governance on LangGraph node functions.

    Args:
        client: CageClient instance for gateway communication
        action: Action name for governance evaluation (e.g., "execute_action")
        agent_id_key: State key containing the agent identifier (default: "agent_id")

    Returns:
        Decorated function that enforces governance before execution
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(state: dict[str, Any]) -> dict[str, Any]:
            agent_id = state.get(agent_id_key, "unknown")
            proposed_action = state.get("proposed_action", {})
            context = state.get("context", {})

            logger.debug(
                "Intercepting LangGraph node execution: action=%s, agent_id=%s, func=%s",
                action,
                agent_id,
                func.__name__,
            )

            try:
                envelope = await client.validate_action(
                    action=action,
                    parameters=proposed_action,
                    agent_id=agent_id,
                    context=context,
                )
            except PolicyViolationException as exc:
                logger.warning(
                    "Action %s DENIED for agent %s: %s, audit_id=%s",
                    action,
                    agent_id,
                    exc.reason_code,
                    exc.audit_id,
                )
                raise
            except DeferralPending as exc:
                logger.info(
                    "Action %s DEFERRED for agent %s: ticket_id=%s, expires_at=%s",
                    action,
                    agent_id,
                    exc.ticket_id,
                    exc.expires_at.isoformat(),
                )
                raise

            logger.info(
                "Action %s ALLOWED for agent %s, executing node %s",
                action,
                agent_id,
                func.__name__,
            )

            state["governance_envelope"] = envelope
            state["governance_status"] = "ALLOWED"
            return await func(state)

        return wrapper  # type: ignore[return-value]

    return decorator
