#!/usr/bin/env python3
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
╔══════════════════════════════════════════════════════════════════════════════╗
║      CAGE · LANGGRAPH INTEGRATION · Three-Act Demo                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

A self-contained walkthrough of the @cage_guard LangGraph integration pattern.
Demonstrates the separation of Policy Enforcement (PEP) from workflow control
using LangGraph conditional edges and the MemorySaver checkpointer.

  ACT 1 — Compliant Trade (ALLOW)
    A compliant trade is submitted. The gateway returns ALLOW.
    The decorated node executes normally.

  ACT 2 — Policy Violation (DENY)
    A prohibited trade is submitted. The gateway returns DENY.
    The decorator raises PolicyViolationException, which is caught and
    routed to a failure/alert node via LangGraph conditional edges.

  ACT 3 — High-Risk Trade (DEFER & HITL Interrupt)
    A high-risk trade is submitted. The gateway returns DEFER.
    The decorator raises DeferralPending. The workflow routes to an approval
    node which triggers a native LangGraph interrupt().
    The workflow pauses, and is resumed by the operator via Command(resume=...).

Usage:
    # Standalone mock mode (default, no infrastructure required)
    uv run python examples/langgraph_cage_guard_demo.py

    # Skip inter-act pauses
    uv run python examples/langgraph_cage_guard_demo.py --no-pause

    # Live mode (requires running CAGE gateway at localhost:8080)
    uv run python examples/langgraph_cage_guard_demo.py --live
"""

import argparse
import asyncio
import sys
import uuid
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
from pathlib import Path
from typing import Any, TypedDict
from unittest.mock import AsyncMock, MagicMock

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.types import Command, interrupt

from src.gateway.client.adapters.langgraph import cage_guard
from src.gateway.client.core import CageClient
from src.gateway.client.envelope import GovernanceEnvelope
from src.gateway.client.exceptions import DeferralPending, PolicyViolationException

# ---------------------------------------------------------------------------
# Terminal colours (no external deps — pure ANSI)
# ---------------------------------------------------------------------------
_TTY = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def RED(t: str) -> str:
    return _c("31;1", t)


def GREEN(t: str) -> str:
    return _c("32;1", t)


def YELLOW(t: str) -> str:
    return _c("33;1", t)


def CYAN(t: str) -> str:
    return _c("36;1", t)


def MAGENTA(t: str) -> str:
    return _c("35;1", t)


def BOLD(t: str) -> str:
    return _c("1", t)


def DIM(t: str) -> str:
    return _c("2", t)


def WHITE(t: str) -> str:
    return _c("97", t)


def _hr(char: str = "─", width: int = 76) -> None:
    print(DIM(char * width))


def _banner(title: str, colour=CYAN) -> None:
    print()
    _hr("═")
    print(colour(f"  {title}"))
    _hr("═")
    print()


def _step(label: str, detail: str = "") -> None:
    print(f"  {BOLD('▶')} {label}" + (f"  {DIM(detail)}" if detail else ""))


def _ok(label: str) -> None:
    print(f"  {GREEN('✓')} {label}")


def _fail(label: str) -> None:
    print(f"  {RED('✗')} {label}")


def _warn(label: str) -> None:
    print(f"  {YELLOW('⚠')} {label}")


def _info(label: str) -> None:
    print(f"  {DIM('·')} {label}")


def _pause(interactive: bool) -> None:
    if interactive:
        input(f"\n  {DIM('[ press ENTER to continue ]')}\n")
    else:
        print()


# ---------------------------------------------------------------------------
# LangGraph Definitions
# ---------------------------------------------------------------------------


class AgentState(TypedDict):
    agent_id: str
    proposed_action: dict[str, Any]
    governance_envelope: Any | None
    governance_status: str | None
    error: str | None
    ticket_id: str | None
    violation_details: dict[str, Any] | None
    trade_result: str | None


def get_mock_client() -> CageClient:
    """Returns a mocked CageClient for zero-infrastructure standalone testing."""
    client = MagicMock(spec=CageClient)

    async def mock_validate_action(action, parameters, agent_id, context):
        ticker = parameters.get("ticker", "")
        amount = parameters.get("amount", 0)

        if ticker == "AAPL":
            # ACT 1: ALLOW
            return GovernanceEnvelope(
                envelope_version="3.0",
                envelope_type="cage_governance_decision",
                issued_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
                issuer={
                    "service": "mock-gateway",
                    "instance_id": "test",
                    "region": "us",
                },
                subject={
                    "action": action,
                    "agent_id": agent_id,
                    "action_hash": "mock",
                    "record_hash": "mock",
                },
                governance_context={
                    "policy_version": "1.0",
                    "tiers_passed": ["tier_1"],
                },
                payload={
                    "decision": "ALLOW",
                    "execution_token": f"token-{uuid.uuid4().hex[:8]}",
                },
                signature={"algorithm": "none", "value": "none", "kid": "none"},
            )
        elif ticker == "PROHIBITED" or amount > 10000:
            # ACT 2: DENY
            raise PolicyViolationException(
                reason_code="PROHIBITED_TICKER",
                violation_details={
                    "message": f"Ticker {ticker} is not allowed or amount exceeds limits."
                },
                audit_id=f"audit-{uuid.uuid4().hex[:8]}",
                recoverable=False,
            )
        else:
            # ACT 3: DEFER
            raise DeferralPending(
                ticket_id=f"ticket-{uuid.uuid4().hex[:8]}",
                defer_reason="High risk trade requires HITL approval.",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                ttl_seconds=3600,
            )

    client.validate_action = AsyncMock(side_effect=mock_validate_action)
    return client


def build_graph(client: CageClient):
    """Builds and compiles the LangGraph workflow with CAGE decorators."""

    # 1. The Core Execution Node (Protected by @cage_guard)
    # The decorator acts as a Policy Enforcement Point (PEP)
    @cage_guard(client=client, action="execute_trade")
    async def execute_trade_guarded(state: AgentState) -> dict[str, Any]:
        action = state.get("proposed_action", {})
        return {
            "trade_result": f"Trade executed: {action.get('amount')} shares of {action.get('ticker')}"
        }

    # 2. The Exception Catcher Node
    # LangGraph conditional edges inspect state, not exceptions.
    # We wrap the PEP to catch governance exceptions and translate them into state updates.
    async def safe_execute_trade(state: AgentState) -> dict[str, Any]:
        try:
            result = await execute_trade_guarded(state)
            return result
        except PolicyViolationException as e:
            return {"error": "DENY", "violation_details": e.violation_details}
        except DeferralPending as e:
            return {"error": "DEFER", "ticket_id": e.ticket_id}

    # 3. Graph Routing
    def route_trade(state: AgentState) -> str:
        if state.get("error") == "DENY":
            return "failure_node"
        elif state.get("error") == "DEFER":
            return "approval_node"
        return END

    # 4. Fallback / Failure Handling Node
    def failure_node(state: AgentState) -> dict[str, Any]:
        details = state.get("violation_details", {})
        msg = details.get("message", "Policy violation")
        return {"trade_result": f"Trade rejected by policy: {msg}"}

    # 5. The Human-In-The-Loop Approval Node
    def approval_node(state: AgentState) -> dict[str, Any]:
        # Suspend graph execution dynamically
        response = interrupt(
            {
                "ticket_id": state.get("ticket_id"),
                "trade": state.get("proposed_action"),
            }
        )

        # Execution resumes here when a Command(resume=...) is passed
        if response.get("approved"):
            return {
                "trade_result": f"Trade approved by {response.get('reviewer')} - {response.get('rationale')}"
            }
        else:
            return {"trade_result": "Trade rejected by human operator."}

    # 6. Graph Compilation
    builder = StateGraph(AgentState)
    builder.add_node("execute_trade", safe_execute_trade)
    builder.add_node("failure_node", failure_node)
    builder.add_node("approval_node", approval_node)

    builder.set_entry_point("execute_trade")
    builder.add_conditional_edges("execute_trade", route_trade)
    builder.add_edge("failure_node", END)
    builder.add_edge("approval_node", END)

    checkpointer = MemorySaver()
    return builder.compile(checkpointer=checkpointer)


# ---------------------------------------------------------------------------
# ACT 1 — Compliant Trade (ALLOW)
# ---------------------------------------------------------------------------


async def act1_allow(interactive: bool, graph: Any) -> bool:
    _banner("ACT 1 · Compliant Trade (ALLOW)", CYAN)
    _step("Scenario", "Agent proposes compliant $100 AAPL trade")
    _step("Expected", "Gateway returns ALLOW → node executes normally")
    _hr()

    config = {"configurable": {"thread_id": "act1-thread"}}
    state = {
        "agent_id": "demo-agent",
        "proposed_action": {"ticker": "AAPL", "amount": 100},
    }

    _info("Submitting graph execution...")
    final_state = await graph.ainvoke(state, config)

    if final_state.get("error") is None and "Trade executed" in final_state.get(
        "trade_result", ""
    ):
        _ok("Trade allowed and executed successfully")
        _info(f"Result: {final_state.get('trade_result')}")

        env = final_state.get("governance_envelope")
        if env:
            _info(
                f"Governance Envelope: {env.payload.get('decision')} (token: {env.payload.get('execution_token')})"
            )

        _pause(interactive)
        return True
    else:
        _fail("Act 1 failed to allow the compliant trade.")
        return False


# ---------------------------------------------------------------------------
# ACT 2 — Policy Violation (DENY)
# ---------------------------------------------------------------------------


async def act2_deny(interactive: bool, graph: Any) -> bool:
    _banner("ACT 2 · Policy Violation (DENY)", RED)
    _step("Scenario", "Agent proposes prohibited ticker (PROHIBITED) trade")
    _step(
        "Expected",
        "Gateway returns DENY → raises PolicyViolationException → conditional edge routes to failure_node",
    )
    _hr()

    config = {"configurable": {"thread_id": "act2-thread"}}
    state = {
        "agent_id": "demo-agent",
        "proposed_action": {"ticker": "PROHIBITED", "amount": 500},
    }

    _info("Submitting graph execution...")
    final_state = await graph.ainvoke(state, config)

    if final_state.get("error") == "DENY":
        _ok("Trade correctly blocked by policy")
        _info(f"Result: {final_state.get('trade_result')}")
        _pause(interactive)
        return True
    else:
        _fail("Act 2 failed to deny the prohibited trade.")
        return False


# ---------------------------------------------------------------------------
# ACT 3 — High-Risk Trade (DEFER & HITL Interrupt)
# ---------------------------------------------------------------------------


async def act3_defer(interactive: bool, graph: Any) -> bool:
    _banner("ACT 3 · High-Risk Trade (DEFER & HITL Interrupt)", MAGENTA)
    _step("Scenario", "Agent proposes $5,000 TSLA trade (High risk)")
    _step(
        "Expected",
        "Gateway returns DEFER → raises DeferralPending → conditional edge routes to approval_node",
    )
    _step(
        "Expected",
        "approval_node calls interrupt() → graph suspends → operator resumes execution",
    )
    _hr()

    config = {"configurable": {"thread_id": "act3-thread"}}
    state = {
        "agent_id": "demo-agent",
        "proposed_action": {"ticker": "TSLA", "amount": 5000},
    }

    _info("1. Submitting graph execution...")

    # Run graph until interrupt
    interrupted = False
    async for event in graph.astream(state, config):
        if "__interrupt__" in event:
            interrupted = True
            interrupt_data = event["__interrupt__"][0].value
            _ok("Graph execution suspended via MemorySaver checkpointer")
            _info(f"Interrupt payload: {interrupt_data}")
            break

    if not interrupted:
        _fail("Graph did not interrupt as expected.")
        return False

    print()
    if interactive:
        print(f"  {YELLOW('►')} Review the trade request. Press ENTER to approve:")
        print(f"  {DIM('  e.g. Approved per risk mandate.')}")
        raw = input(f"  {BOLD('Rationale:')} ").strip()
        rationale = raw or "Mandate compliant"
    else:
        rationale = "Mandate compliant"

    _step("2. Operator resuming execution...")
    resume_command = Command(
        resume={
            "approved": True,
            "reviewer": "risk@firm.com",
            "rationale": rationale,
        }
    )

    _info("Resuming with Command(resume=...)")

    # Resume graph execution
    async for event in graph.astream(resume_command, config):
        if "approval_node" in event:
            result = event["approval_node"]
            _info(f"Resumed execution result: {result.get('trade_result')}")

    final_state = graph.get_state(config).values

    if (
        "trade_result" in final_state
        and "approved" in final_state.get("trade_result", "").lower()
    ):
        _ok("Trade successfully resumed and executed via HITL approval.")
        _pause(interactive)
        return True
    else:
        _fail("Act 3 failed to resume correctly.")
        return False


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------


def _summary(results: dict[str, bool]) -> None:
    _banner("DEMO COMPLETE · LangGraph Integration Summary", WHITE)

    rows = [
        (
            "ACT 1",
            "Compliant Trade (ALLOW)",
            "Gateway ALLOW → @cage_guard completes → Node executes",
        ),
        (
            "ACT 2",
            "Policy Violation (DENY)",
            "Gateway DENY → PolicyViolationException → Conditional Edge routes to fail",
        ),
        (
            "ACT 3",
            "High-Risk Trade (DEFER & HITL)",
            "Gateway DEFER → DeferralPending → approval_node interrupt() → Resume",
        ),
    ]

    for (act, title, detail), ok in zip(rows, results.values(), strict=False):
        status = GREEN("PASS") if ok else RED("FAIL")
        print(f"  {status}  {BOLD(act)}  {title}")
        _info(detail)

    overall = all(results.values())
    print()
    if overall:
        _ok(BOLD("All acts passed — LangGraph demo complete"))
    else:
        _fail(BOLD("One or more acts failed"))
    _hr()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main_async() -> int:
    parser = argparse.ArgumentParser(
        description="CAGE LangGraph Integration Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--no-pause",
        action="store_true",
        help="Skip inter-act pause prompts (non-interactive / CI mode)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use live CAGE gateway instead of standalone mock",
    )
    args = parser.parse_args()

    interactive = not args.no_pause and sys.stdout.isatty()

    if args.live:
        client = CageClient(gateway_url="http://localhost:8080")
        _info("Running in LIVE mode (requires Gateway on localhost:8080)")
    else:
        client = get_mock_client()
        _info("Running in MOCK mode (zero-infrastructure)")

    graph = build_graph(client)
    results: dict[str, bool] = {}

    try:
        results["act1"] = await act1_allow(interactive, graph)
        results["act2"] = await act2_deny(interactive, graph)
        results["act3"] = await act3_defer(interactive, graph)
    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW('Demo interrupted.')}\n")
        return 130
    finally:
        if args.live:
            await client.aclose()

    _summary(results)
    return 0 if all(results.values()) else 1


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    sys.exit(main())
