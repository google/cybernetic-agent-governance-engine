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
verdicts.
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
    DEFAULT_TRADER_ROLE,
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


def test_trade_params_never_take_the_role_from_the_source() -> None:
    params = trade_params({"symbol": "AAPL", "amount": "500", "trader_role": "senior"})
    assert params == {
        "action": TRADE_ACTION,
        "symbol": "AAPL",
        "amount": 500.0,
        "currency": "USD",
        "trader_role": DEFAULT_TRADER_ROLE,
        "confidence": 1.0,
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
    assert params["trader_role"] == DEFAULT_TRADER_ROLE
    assert (params["symbol"], params["amount"], params["currency"]) == (
        "AAPL",
        500.0,
        "USD",
    )


@pytest.mark.asyncio
async def test_trade_like_step_names_are_previewed_as_the_registered_action(
    monkeypatch,
) -> None:
    calls = _install_dry_run(monkeypatch, "ALLOW")
    step = {**_TRADE_STEP, "action": "buy_stock"}

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
    assert seen["params"]["trader_role"] == DEFAULT_TRADER_ROLE


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
