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
Agent Adapters — bridge between ADK agent objects and LangGraph node functions.

Provides:
  - inject_agent(name, agent): register a named agent instance (useful in tests).
  - execution_analyst_node(state): LangGraph node that invokes the execution analyst.
  - run_adk_agent(agent, state): callable shim that tests can patch.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("graph.nodes.adapters")

# ---------------------------------------------------------------------------
# Agent registry — allows tests to inject mock agents
# ---------------------------------------------------------------------------

_AGENT_REGISTRY: Dict[str, Any] = {}


def inject_agent(name: str, agent: Any) -> None:
    """Register *agent* under *name* in the local agent registry.

    This is useful in tests to inject mock objects without touching
    production code paths.
    """
    _AGENT_REGISTRY[name] = agent
    logger.debug("inject_agent: registered agent '%s'", name)


def _get_agent(name: str) -> Optional[Any]:
    return _AGENT_REGISTRY.get(name)


# ---------------------------------------------------------------------------
# Stub callable that tests can patch
# ---------------------------------------------------------------------------

def run_adk_agent(agent: Any, state: Dict[str, Any]) -> Any:
    """Run an ADK agent against the given state and return its response.

    In production this invokes the agent's execution loop.
    In tests this function is patched via ``adapters.run_adk_agent = mock_run``.
    """
    # Try the standard ADK interface
    if hasattr(agent, "run"):
        return agent.run(state)
    if hasattr(agent, "invoke"):
        return agent.invoke(state)
    raise TypeError(f"Agent {agent!r} does not support run() or invoke()")


# ---------------------------------------------------------------------------
# LangGraph node: execution_analyst
# ---------------------------------------------------------------------------

_PROFILE_CLARIFICATION = (
    "Before I can build an execution plan, I need a bit more information:\n"
    "1. Risk Attitude: Are you Conservative, Moderate, or Aggressive?\n"
    "2. Investment Period: Short-term, Mid-term, or Long-term?\n\n"
    "Please reply with your Risk Attitude and Investment Period."
)


def execution_analyst_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """LangGraph node that invokes the Execution Analyst agent.

    Profile gating: if the user has not yet provided ``risk_attitude`` and
    ``investment_period``, the node returns a clarification request instead
    of invoking the agent.

    Returns a state update dict with at minimum a ``messages`` key.
    """
    risk_attitude: Optional[str] = state.get("risk_attitude")
    investment_period: Optional[str] = state.get("investment_period")

    # Gate: ask for profile if missing
    if not risk_attitude or not investment_period:
        logger.info("execution_analyst_node: profile incomplete — requesting clarification")
        return {
            "messages": [
                ("assistant", _PROFILE_CLARIFICATION)
            ],
        }

    # Profile is present — run the agent
    agent = _get_agent("execution_analyst")
    if agent is None:
        logger.warning("execution_analyst_node: no agent registered — returning empty plan")
        return {
            "messages": [],
            "execution_plan_output": None,
        }

    try:
        response = run_adk_agent(agent, state)
        # Attempt to extract a structured plan from the response
        plan = None
        if hasattr(response, "answer"):
            import json  # noqa: PLC0415
            try:
                plan = json.loads(response.answer)
            except Exception:
                plan = {"raw": response.answer}
        elif isinstance(response, dict):
            plan = response

        return {
            "messages": [],
            "execution_plan_output": plan,
        }
    except Exception as exc:
        logger.error("execution_analyst_node: agent failed — %s", exc)
        return {
            "messages": [("system", f"Execution analyst error: {exc}")],
            "execution_plan_output": None,
        }
