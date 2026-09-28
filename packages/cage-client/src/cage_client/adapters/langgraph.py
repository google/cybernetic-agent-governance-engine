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

This module provides the `@cage_guard` decorator that integrates CAGE governance
into LangGraph-based agent workflows. It intercepts LangGraph node execution and
submits proposed actions to the CAGE Gateway for pre-execution validation.

The decorator handles the tri-state governance response:
  - ALLOW → Node executes normally with governance envelope in state
  - DENY → Raises PolicyViolationException for LangGraph error handlers
  - DEFER → Raises DeferralPending for checkpointer interrupt/parking

Architecture Integration:
    ┌─────────────┐
    │ LangGraph   │
    │ Workflow    │
    └──────┬──────┘
           │
    ┌──────▼──────────────┐
    │  @cage_guard        │  ◄── Intercepts node execution
    │  Decorator          │
    └──────┬──────────────┘
           │
    ┌──────▼──────────────┐
    │  CageClient         │  ◄── Submits to gateway
    │  validate_action()  │
    └──────┬──────────────┘
           │
    ┌──────▼──────────────┐
    │  CAGE Gateway PDP   │
    └─────────────────────┘

Usage:
    from cage_client import CageClient
    from cage_client.adapters.langgraph import cage_guard

    # Initialize client (typically once at app startup)
    cage_client = CageClient(
        gateway_url="https://cage-gateway.example.com",
    )

    # Decorate LangGraph node functions
    @cage_guard(client=cage_client, action="execute_action")
    async def execute_action_node(state: dict[str, Any]) -> dict[str, Any]:
        # This node only runs if governance allows
        trade_params = state["proposed_action"]
        result = await execute_action(**trade_params)
        return {"trade_result": result}

    # LangGraph workflow definition
    from langgraph.graph import StateGraph

    workflow = StateGraph()
    workflow.add_node("execute_action", execute_action_node)
    # ... add more nodes and edges

    # Error handling in LangGraph
    @workflow.on_error
    async def handle_governance_error(state, error):
        if isinstance(error, PolicyViolationException):
            # Route to replanning node
            return {"next_node": "replan", "violation": error.violation_details}
        elif isinstance(error, DeferralPending):
            # Park checkpoint, wait for HITL approval
            return {"next_node": "__interrupt__", "ticket_id": error.ticket_id}
        raise error

State Contract:
    The decorator expects the LangGraph state dictionary to contain:
      - state["proposed_action"]: dict - Parameters for the governed action
      - state[agent_id_key]: str - Agent identifier (default key: "agent_id")
      - state["context"]: dict (optional) - Additional governance context

    On success (ALLOW), the decorator injects:
      - state["governance_envelope"]: GovernanceEnvelope - Signed decision
      - state["governance_status"]: str - Always "ALLOWED"

Error Propagation:
    The decorator propagates governance exceptions directly to LangGraph's
    error handling system. LangGraph checkpointers can interrupt on
    DeferralPending and resume execution after human approval.

    - PolicyViolationException → LangGraph can route to replanning
    - DeferralPending → LangGraph can park checkpoint for HITL
    - CageGatewayError → LangGraph can implement retry/fallback
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

# Type variable for decorated function
F = TypeVar("F", bound=Callable[..., Any])


def cage_guard(
    client: CageClient,
    action: str,
    agent_id_key: str = "agent_id",
) -> Callable[[F], F]:
    """
    Decorator that enforces CAGE governance on LangGraph node functions.

    This decorator intercepts LangGraph node execution and submits the proposed
    action to the CAGE Gateway for pre-execution validation. It handles the
    tri-state response (ALLOW/DENY/DEFER) and propagates exceptions to LangGraph's
    error handling system.

    Args:
        client: CageClient instance for gateway communication
        action: Action name for governance evaluation (e.g., "execute_action")
        agent_id_key: State key containing the agent identifier (default: "agent_id")

    Returns:
        Decorated function that enforces governance before execution

    Raises:
        PolicyViolationException: Action denied by governance policy
        DeferralPending: Action requires human-in-the-loop approval
        CageGatewayError: Gateway communication failure

    Example:
        @cage_guard(client=cage_client, action="access_pii")
        async def access_customer_data(state: dict[str, Any]) -> dict[str, Any]:
            customer_id = state["proposed_action"]["customer_id"]
            data = await fetch_customer_data(customer_id)
            return {"customer_data": data}

        # State contract:
        state = {
            "agent_id": "advisor-prod-v3",
            "proposed_action": {"customer_id": "12345"},
            "context": {"session_id": "abc123"}
        }
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(state: dict[str, Any]) -> dict[str, Any]:
            # Extract governance parameters from LangGraph state
            agent_id = state.get(agent_id_key, "unknown")
            proposed_action = state.get("proposed_action", {})
            context = state.get("context", {})

            logger.debug(
                f"Intercepting LangGraph node execution: action={action}, "
                f"agent_id={agent_id}, func={func.__name__}"
            )

            # Submit action to CAGE Gateway for validation
            # This will raise PolicyViolationException or DeferralPending on deny/defer
            try:
                envelope = await client.validate_action(
                    action=action,
                    parameters=proposed_action,
                    agent_id=agent_id,
                    context=context,
                )
            except PolicyViolationException as e:
                logger.warning(
                    f"Action {action} DENIED for agent {agent_id}: "
                    f"{e.reason_code}, audit_id={e.audit_id}"
                )
                # Propagate to LangGraph error handler
                raise

            except DeferralPending as e:
                logger.info(
                    f"Action {action} DEFERRED for agent {agent_id}: "
                    f"ticket_id={e.ticket_id}, expires_at={e.expires_at.isoformat()}"
                )
                # Propagate to LangGraph checkpointer for parking
                raise

            # Governance ALLOWED: Inject envelope into state and execute node
            logger.info(
                f"Action {action} ALLOWED for agent {agent_id}, "
                f"executing node {func.__name__}"
            )

            # Augment state with governance decision
            state["governance_envelope"] = envelope
            state["governance_status"] = "ALLOWED"

            # Execute the original node function
            result = await func(state)

            return result

        return wrapper  # type: ignore[return-value]

    return decorator
