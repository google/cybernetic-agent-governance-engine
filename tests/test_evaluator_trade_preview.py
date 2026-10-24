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

"""The evaluator previews the trade the gateway will actually see.

Regression for the 2026-10-03 in-cluster benchmark
(``docs/paper/measurements/2026-10-03-57556228/PROVENANCE.md``). All 4 benign
trade prompts ended in "The trade was rejected ...". The evaluator's dry run
sent the planner step's raw parameters without ``trader_role``.
``trade_governance.rego`` denies any action other than ``market_analysis``
from an unknown role, so OPA returned DENY. The evaluator also treated
REQUIRE_APPROVAL (FTRA: an irreversible trade needs a human) as a rejection
and re-planned until the loop cap gave up. It now builds the payload with the
same ``trade_contract`` as the pre-trade gate and proceeds on the same
verdicts. Since GHSA-w39v-5v7h-fxg9 neither path sends a role at all: the
gateway binds ``trader_role`` from the advisor's verified workload identity.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from src.cage_finance import REGISTERED_ACTIONS
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.ftra.classifier import _load_registry_document
from src.governed_financial_advisor.graph.nodes import evaluator_node as evaluator_mod
from src.governed_financial_advisor.graph.nodes import safety_node as safety_mod
from src.governed_financial_advisor.graph.nodes.trade_contract import (
    PROCEED_VERDICTS,
    TRADE_ACTION,
    trade_params,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_REPO = Path(__file__).resolve().parents[1]

_TRADE_STEP = {
    "id": "s3",
    "action": "execute_trade",
    "description": "Buy $500 of AAPL at market price",
    # A model-written step may assert a role; it must not reach the gateway.
    "parameters": {
        "symbol": "AAPL",
        "amount": 500,
        "currency": "USD",
        "trader_role": "senior",
    },
}

#: ``_TRADE_STEP`` with a confidence that clears the reuse threshold. A step
#: without one is previewed at 0.0 (the committing tool's default), and its
#: ``ALLOW`` verdict is never cached.
_CONFIDENT_TRADE_STEP = {
    **_TRADE_STEP,
    "parameters": {**_TRADE_STEP["parameters"], "confidence": 0.99},
}


def _plan(*steps: dict[str, Any]) -> dict[str, Any]:
    return {
        "rationale": "Moderate investor, long horizon; small single-tranche entry.",
        "steps": [
            {
                "id": "s1",
                "action": "check_market_status",
                "description": "open?",
                "parameters": {"symbol": "AAPL"},
            },
            *steps,
        ],
    }


def _install_dry_run(monkeypatch, verdict: str) -> list[tuple[str, dict[str, Any]]]:
    calls: list[tuple[str, dict[str, Any]]] = []

    async def fake(
        target_tool: str, target_params: dict[str, Any], risk_profile: str = "Medium"
    ):
        calls.append((target_tool, target_params))
        return {
            "verdict": verdict,
            "message": f"dry run {verdict}",
            "opa_results": None,
        }

    monkeypatch.setattr(evaluator_mod, "simulate_governance_check", fake)
    return calls


# ---------------------------------------------------------------------------
# trade_contract
# ---------------------------------------------------------------------------


def test_trade_params_never_carry_a_role_or_trader() -> None:
    # The gateway binds both from the verified caller identity.
    params = trade_params(
        {
            "symbol": "AAPL",
            "amount": "500",
            "trader_role": "senior",
            "trader_id": "desk-7",
        }
    )
    assert params == {
        "action": TRADE_ACTION,
        "symbol": "AAPL",
        "amount": 500.0,
        "currency": "USD",
        "confidence": 0.0,
        "side": "buy",
    }


def test_trade_params_reject_a_non_numeric_amount() -> None:
    with pytest.raises(ValueError):
        trade_params({"amount": "five shares"})


def test_proceed_verdicts() -> None:
    assert {v.value for v in PROCEED_VERDICTS} == {
        "ALLOW",
        "NARROW",
        "REQUIRE_APPROVAL",
    }


# ---------------------------------------------------------------------------
# evaluator_node
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dry_run_previews_the_canonical_trade(monkeypatch) -> None:
    calls = _install_dry_run(monkeypatch, "ALLOW")

    await evaluator_mod.evaluator_node({"execution_plan_output": _plan(_TRADE_STEP)})

    [(tool, params)] = calls
    assert tool == TRADE_ACTION
    assert "trader_role" not in params  # the model's "senior" never leaves
    assert (params["symbol"], params["amount"], params["currency"]) == (
        "AAPL",
        500.0,
        "USD",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["buy", "SELL", "Trade"])
async def test_trade_step_names_are_previewed_as_the_registered_action(
    monkeypatch, name: str
) -> None:
    # Names match TRADE_STEP_ACTIONS exactly, ignoring case. Substrings such
    # as ``buy_stock`` are not trades (#513, tests/test_trade_contract.py).
    calls = _install_dry_run(monkeypatch, "ALLOW")
    step = {**_TRADE_STEP, "action": name}

    await evaluator_mod.evaluator_node({"execution_plan_output": _plan(step)})

    assert calls[0][0] == TRADE_ACTION


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("verdict", "approved", "needs_approval"),
    [
        ("ALLOW", True, False),
        ("NARROW", True, False),
        ("REQUIRE_APPROVAL", True, True),
        ("DENY", False, False),
        ("DEFER", False, False),
        ("ERROR", False, False),
    ],
)
async def test_verdict_routing(monkeypatch, verdict, approved, needs_approval) -> None:
    _install_dry_run(monkeypatch, verdict)

    out = await evaluator_mod.evaluator_node(
        {"execution_plan_output": _plan(_TRADE_STEP)}
    )

    assert out["risk_status"] == ("APPROVED" if approved else "REJECTED_REVISE")
    assert out["evaluation_result"]["verdict"] == (
        "APPROVED" if approved else "REJECTED"
    )
    assert out["evaluation_result"]["requires_approval"] is needs_approval


@pytest.mark.asyncio
async def test_invalid_amount_is_sent_back_without_a_dry_run(monkeypatch) -> None:
    calls = _install_dry_run(monkeypatch, "ALLOW")
    step = {**_TRADE_STEP, "parameters": {"symbol": "AAPL", "amount": "five shares"}}

    out = await evaluator_mod.evaluator_node({"execution_plan_output": _plan(step)})

    assert calls == []
    assert out["risk_status"] == "REJECTED_REVISE"


# ---------------------------------------------------------------------------
# safety_check_node shares the contract
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_safety_gate_submits_the_same_payload(monkeypatch) -> None:
    seen: dict[str, Any] = {}

    class _Client:
        async def validate_action(
            self, *, action: str, params: dict[str, Any]
        ) -> dict[str, Any]:
            seen.update(action=action, params=params)
            return {"verdict": GovernanceDecision.ALLOW, "envelope_id": "e1"}

    monkeypatch.setattr(safety_mod, "GatewayClient", _Client)
    plan = {"action": "execute_trade", **_TRADE_STEP["parameters"]}

    out = await safety_mod.safety_check_node(
        {"execution_plan_output": plan, "consecutive_denials": 0}
    )

    assert out["safety_status"] == "APPROVED"
    assert seen["action"] == TRADE_ACTION
    assert seen["params"] == trade_params(plan)
    assert "trader_role" not in seen["params"]


# ---------------------------------------------------------------------------
# FTRA: the planner's read-only steps are registered
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["check_market_status", "check_balance"])
def test_planner_read_only_steps_are_registered(action) -> None:
    # agent.py "Available Actions": execute_trade, check_market_status,
    # check_balance. An unregistered step is IRREVERSIBLE_TERMINAL to FTRA,
    # which parked every trade plan for a human regardless of the trade.
    assert action in REGISTERED_ACTIONS
    runtime = _load_registry_document(
        _REPO / "config" / "ftra" / "terminal_registry.json"
    )
    assert runtime.terminals[action] == "READ_ONLY"
    generated = json.loads(
        (_REPO / "src/cage_finance/stpa/terminal_registry.json").read_text()
    )
    assert generated["terminals"][action] == "READ_ONLY"


# ---------------------------------------------------------------------------
# Structured ExecutionPlan extraction & ALLOW routing-verdict reuse
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_safety_gate_extracts_trade_step_from_structured_execution_plan(
    monkeypatch,
) -> None:
    """safety_check_node extracts the trade step from a structured ExecutionPlan dict."""
    seen: dict[str, Any] = {}

    class _Client:
        async def validate_action(
            self, *, action: str, params: dict[str, Any]
        ) -> dict[str, Any]:
            seen.update(action=action, params=params)
            return {
                "verdict": GovernanceDecision.ALLOW,
                "envelope_id": "e1",
                "signature": "sig-1",
            }

    monkeypatch.setattr(safety_mod, "GatewayClient", _Client)
    structured_plan = _plan(_CONFIDENT_TRADE_STEP)

    out = await safety_mod.safety_check_node(
        {"execution_plan_output": structured_plan, "consecutive_denials": 0}
    )

    assert out["safety_status"] == "APPROVED"
    assert seen["action"] == TRADE_ACTION
    assert seen["params"] == trade_params(_CONFIDENT_TRADE_STEP["parameters"])
    assert out["routing_verdict_cache"] is not None
    assert out["routing_verdict_cache"]["verdict"] == "ALLOW"


@pytest.mark.asyncio
async def test_allow_routing_verdict_reused_across_evaluator_safety_and_tool_guard(
    monkeypatch,
) -> None:
    """A fresh ALLOW verdict from evaluator_node is reused by safety_check_node and gateway_tool_guard."""
    from langchain_core.messages import AIMessage, ToolMessage

    from src.governed_financial_advisor.graph.governance.tool_guard import (
        gateway_tool_guard,
    )

    _install_dry_run(monkeypatch, "ALLOW")
    structured_plan = _plan(_CONFIDENT_TRADE_STEP)

    eval_out = await evaluator_mod.evaluator_node(
        {"execution_plan_output": structured_plan}
    )
    cache = eval_out["routing_verdict_cache"]
    assert cache is not None
    assert cache["verdict"] == "ALLOW"

    validate_calls = 0

    class _FailingClient:
        async def validate_action(
            self, *, action: str, params: dict[str, Any]
        ) -> dict[str, Any]:
            nonlocal validate_calls
            validate_calls += 1
            raise AssertionError("validate_action should be skipped on fresh ALLOW hit")

    monkeypatch.setattr(safety_mod, "GatewayClient", _FailingClient)

    safety_out = await safety_mod.safety_check_node(
        {
            "execution_plan_output": structured_plan,
            "consecutive_denials": 1,
            "routing_verdict_cache": cache,
        }
    )
    assert safety_out["safety_status"] == "APPROVED"
    assert safety_out["consecutive_denials"] == 0
    assert validate_calls == 0

    from src.governed_financial_advisor.graph.governance import tool_guard as guard_mod

    monkeypatch.setattr(guard_mod, "GatewayClient", _FailingClient)

    executed = 0

    async def _fake_executor(state: dict[str, Any]) -> dict[str, Any]:
        nonlocal executed
        executed += 1
        return {"messages": [ToolMessage(content="EXECUTED", tool_call_id="c1")]}

    tool_call = {
        "name": "execute_trade_action",
        "id": "c1",
        "args": {
            "symbol": "AAPL",
            "amount": 500.0,
            "currency": "USD",
            "confidence": 0.99,
            "side": "buy",
        },
    }
    guard_out = await gateway_tool_guard("execute_trade", approvable=True)(
        _fake_executor
    )(
        {
            "messages": [AIMessage(content="", tool_calls=[tool_call])],
            "routing_verdict_cache": safety_out["routing_verdict_cache"],
        }
    )
    assert executed == 1
    assert validate_calls == 0
    assert guard_out["governance_status"] == "ALLOWED"
    assert guard_out["governance_envelope"]["verdict"] == "ALLOW"
    assert guard_out["routing_verdict_cache"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("verdict", ["NARROW", "REQUIRE_APPROVAL"])
async def test_narrow_and_require_approval_never_populate_or_reuse_routing_cache(
    monkeypatch, verdict: str
) -> None:
    """NARROW and REQUIRE_APPROVAL must never reuse a cached verdict."""
    _install_dry_run(monkeypatch, verdict)
    structured_plan = _plan(_TRADE_STEP)

    eval_out = await evaluator_mod.evaluator_node(
        {"execution_plan_output": structured_plan}
    )
    assert eval_out["routing_verdict_cache"] is None

    validate_calls = 0

    class _RecordingClient:
        async def validate_action(
            self, *, action: str, params: dict[str, Any]
        ) -> dict[str, Any]:
            nonlocal validate_calls
            validate_calls += 1
            return {
                "verdict": getattr(GovernanceDecision, verdict),
                "deferred_id": "d-1" if verdict == "REQUIRE_APPROVAL" else None,
            }

    monkeypatch.setattr(safety_mod, "GatewayClient", _RecordingClient)

    safety_out = await safety_mod.safety_check_node(
        {
            "execution_plan_output": structured_plan,
            "consecutive_denials": 0,
            "routing_verdict_cache": {
                "params_digest": "any",
                "verdict": verdict,
                "at": 1e12,
                "envelope": {"verdict": verdict},
            },
        }
    )
    assert validate_calls == 1
    assert safety_out["safety_status"] == "APPROVED"
    assert safety_out["routing_verdict_cache"] is None


@pytest.mark.asyncio
async def test_expired_or_mismatched_routing_cache_calls_validate_action(
    monkeypatch,
) -> None:
    """Expired TTL, parameter drift, role change, or low confidence forces a fresh validate-action call."""
    from src.governed_financial_advisor.graph.nodes.trade_contract import (
        build_routing_verdict_cache,
        reusable_allow_verdict,
    )

    params = trade_params(_CONFIDENT_TRADE_STEP["parameters"])
    cache = build_routing_verdict_cache(params, verdict="ALLOW", now=100.0)
    assert cache is not None

    # Within 30s TTL and matching params -> hits cache
    assert reusable_allow_verdict(cache, params, now=125.0, ttl_s=30.0) is not None
    # Expired (> 30s) -> misses cache
    assert reusable_allow_verdict(cache, params, now=131.0, ttl_s=30.0) is None
    # Amount changed -> misses cache
    assert (
        reusable_allow_verdict(
            cache, {**params, "amount": 501.0}, now=110.0, ttl_s=30.0
        )
        is None
    )
    # Side changed -> misses cache
    assert (
        reusable_allow_verdict(cache, {**params, "side": "sell"}, now=110.0, ttl_s=30.0)
        is None
    )
    # A tool call that still names trader_role / trader_id carries a field the
    # digest does not bind (the gateway binds who trades) -> misses cache, so
    # it is always re-validated
    for claim in ({"trader_role": "senior"}, {"trader_id": "desk-7"}):
        assert (
            reusable_allow_verdict(cache, {**params, **claim}, now=110.0, ttl_s=30.0)
            is None
        )
    # Confidence below 0.95 -> misses cache
    assert (
        reusable_allow_verdict(
            cache, {**params, "confidence": 0.5}, now=110.0, ttl_s=30.0
        )
        is None
    )
