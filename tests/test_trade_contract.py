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

"""The advisor's trade contract binds the whole order and the whole plan (#513).

Before the fix, ``trade_contract``:

* matched trade steps by substring, so ``buyer_survey``, ``executed_report``
  and ``bestseller_scan`` were trades that failed with "Invalid trade amount
  None", and each refusal counted toward ``MAX_CONSECUTIVE_DENIALS``;
* extracted only a plan's first trade step, so ``safety_check_node`` reported
  APPROVED and reset the denial budget on step 1 alone;
* previewed a missing ``confidence`` as ``1.0`` while the committing tool
  defaults it to ``0.0``;
* reused a cached ``ALLOW`` verdict for an order that differed in a field the
  digest did not bind (``limit_price``, ``account_id``, ``order_type``,
  ``venue``, ``agent_id``, ``transaction_id``, ...).

The safety-node tests drive the real ``GatewayClient`` over an
``httpx.MockTransport``, so every fail-closed path of a multi-step plan is
observed end to end.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from langchain_core.messages import AIMessage, ToolMessage

from src.cage_finance.tools.tool_provider import execute_trade_action
from src.gateway.governance.decisions import GovernanceDecision
from src.governed_financial_advisor.graph.governance import tool_guard as guard_mod
from src.governed_financial_advisor.graph.nodes import evaluator_node as evaluator_mod
from src.governed_financial_advisor.graph.nodes.safety_node import (
    MAX_CONSECUTIVE_DENIALS,
    safety_check_node,
)
from src.governed_financial_advisor.graph.nodes.trade_contract import (
    DEFAULT_CONFIDENCE,
    TRADE_ACTION,
    TRADE_PARAM_KEYS,
    TRADE_STEP_ACTIONS,
    build_routing_verdict_cache,
    canonical_trade_digest,
    extract_trade_steps,
    is_trade_action,
    reusable_allow_verdict,
    trade_params,
)
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient

pytestmark = [pytest.mark.unit, pytest.mark.local]

Handler = Callable[[httpx.Request], httpx.Response]

#: A confident order as a tool call carries it (``gateway_tool_guard`` adds
#: ``tool_name`` and ``action`` before asking for reuse).
_ORDER: dict[str, Any] = {
    "symbol": "AAPL",
    "amount": 1000.0,
    "currency": "USD",
    "side": "buy",
    "confidence": 0.97,
}
_CALL_PARAMS: dict[str, Any] = {
    **_ORDER,
    "tool_name": "execute_trade_action",
    "action": TRADE_ACTION,
}

#: Order fields outside the canonical payload; each one must prevent reuse.
_EXTRA_FIELDS = [
    ("limit_price", 1.0),
    ("account_id", "other-account"),
    ("order_type", "market"),
    ("venue", "DARKPOOL"),
    ("agent_id", "someone-else"),
    ("trader_id", "other-trader"),
    ("transaction_id", "other-tx"),
]

_SUBSTRING_NAMES = [
    "buyer_survey",
    "executed_report",
    "bestseller_scan",
    "buy_stock",
    "execute",
    "trade_history",
    "presell",
    " buy",
    "sell ",
]
_EXACT_NAMES = [
    "execute_trade",
    "EXECUTE_TRADE",
    "trade",
    "Trade",
    "buy",
    "BUY",
    "sell",
    "Sell",
]


def _step(action: str, **parameters: Any) -> dict[str, Any]:
    return {
        "id": f"s-{action}",
        "action": action,
        "description": action,
        "parameters": parameters,
    }


def _trade(symbol: str, **parameters: Any) -> dict[str, Any]:
    return _step(
        "execute_trade",
        symbol=symbol,
        amount=parameters.pop("amount", 10.0),
        currency="USD",
        **parameters,
    )


def _plan(*steps: dict[str, Any]) -> dict[str, Any]:
    return {
        "rationale": "Moderate investor, long horizon; staged entry.",
        "steps": [_step("check_market_status", symbol="AAA"), *steps],
    }


# ---------------------------------------------------------------------------
# Trade-step recognition: exact, case-insensitive allowlist
# ---------------------------------------------------------------------------


def test_trade_step_actions_are_the_planner_action_and_the_bare_verbs() -> None:
    assert frozenset({"execute_trade", "trade", "buy", "sell"}) == TRADE_STEP_ACTIONS


@pytest.mark.parametrize("name", _SUBSTRING_NAMES)
def test_substring_names_are_not_trades(name: str) -> None:
    assert not is_trade_action(name)
    # No parameters: as a trade, this step failed with "Invalid trade amount None".
    assert extract_trade_steps(_plan(_step(name))) == []


@pytest.mark.parametrize("name", _EXACT_NAMES)
def test_exact_names_are_trades_in_any_case(name: str) -> None:
    assert is_trade_action(name)
    assert extract_trade_steps(_plan(_step(name, symbol="AAPL", amount=10))) == [
        trade_params({"symbol": "AAPL", "amount": 10})
    ]


@pytest.mark.parametrize("action", [None, 1, ["buy"], {"buy": 1}])
def test_non_string_actions_are_not_trades(action: Any) -> None:
    assert not is_trade_action(action)


def test_a_flat_plan_uses_the_same_match() -> None:
    assert extract_trade_steps({"action": "SELL", "symbol": "X", "amount": 1}) == [
        trade_params({"symbol": "X", "amount": 1})
    ]
    assert extract_trade_steps({"action": "buyer_survey", "amount": 1}) == []


# ---------------------------------------------------------------------------
# Every trade step of a plan is extracted
# ---------------------------------------------------------------------------


def test_every_trade_step_is_extracted_in_plan_order() -> None:
    plan = _plan(
        _step("buy", symbol="AAA", amount=10),
        _step("check_balance", required_amount=10),
        _step("sell", symbol="BBB", amount=1e9, side="sell"),
    )

    steps = extract_trade_steps(plan)

    assert [(s["symbol"], s["amount"], s["side"]) for s in steps] == [
        ("AAA", 10.0, "buy"),
        ("BBB", 1e9, "sell"),
    ]
    assert all(s["action"] == TRADE_ACTION for s in steps)


def test_one_malformed_trade_step_fails_the_whole_plan() -> None:
    with pytest.raises(ValueError, match="amount"):
        extract_trade_steps(_plan(_trade("AAA"), _step("sell", symbol="BBB")))


# ---------------------------------------------------------------------------
# confidence: the committing tool's default, validated
# ---------------------------------------------------------------------------


def test_missing_confidence_previews_the_committing_tool_default() -> None:
    tool_default = (
        inspect.signature(execute_trade_action).parameters["confidence"].default
    )

    assert tool_default == DEFAULT_CONFIDENCE == 0.0
    assert trade_params({"symbol": "AAPL", "amount": 5})["confidence"] == tool_default


def test_missing_confidence_is_not_cacheable() -> None:
    order = {k: v for k, v in _ORDER.items() if k != "confidence"}

    assert build_routing_verdict_cache(order, verdict="ALLOW") is None
    assert build_routing_verdict_cache(trade_params(order), verdict="ALLOW") is None


@pytest.mark.parametrize(
    "raw",
    [
        True,
        False,
        None,
        "high",
        [0.99],
        {"confidence": 0.99},
        float("nan"),
        float("inf"),
        float("-inf"),
        "nan",
        "inf",
    ],
)
def test_invalid_confidence_is_rejected(raw: Any) -> None:
    with pytest.raises(ValueError, match="confidence"):
        trade_params({"amount": 5, "confidence": raw})


@pytest.mark.parametrize(("raw", "expected"), [(1, 1.0), ("0.97", 0.97), (0.5, 0.5)])
def test_numeric_confidence_is_sent_as_a_float(raw: Any, expected: float) -> None:
    confidence = trade_params({"amount": 5, "confidence": raw})["confidence"]
    assert type(confidence) is float
    assert confidence == expected


# ---------------------------------------------------------------------------
# Routing-verdict reuse binds the full order
# ---------------------------------------------------------------------------


def test_trade_param_keys_are_the_canonical_payload() -> None:
    assert set(trade_params(_ORDER)) == TRADE_PARAM_KEYS


def _cache() -> dict[str, Any]:
    cache = build_routing_verdict_cache(trade_params(_ORDER), verdict="ALLOW", now=0.0)
    assert cache is not None
    return cache


def _reused(cache: dict[str, Any], params: dict[str, Any]) -> bool:
    return reusable_allow_verdict(cache, params, now=5.0, ttl_s=30.0) is not None


def test_the_exact_order_reuses_its_verdict() -> None:
    cache = _cache()

    assert _reused(cache, trade_params(_ORDER))
    assert _reused(cache, _CALL_PARAMS)


@pytest.mark.parametrize(("field", "value"), _EXTRA_FIELDS)
def test_each_extra_field_prevents_reuse(field: str, value: Any) -> None:
    assert not _reused(_cache(), {**_CALL_PARAMS, field: value})


@pytest.mark.parametrize(("field", "value"), _EXTRA_FIELDS)
def test_each_extra_field_prevents_caching(field: str, value: Any) -> None:
    params = {**trade_params(_ORDER), field: value}

    assert build_routing_verdict_cache(params, verdict="ALLOW") is None
    with pytest.raises(ValueError, match=field):
        canonical_trade_digest(params)


def test_another_action_prevents_reuse() -> None:
    assert not _reused(_cache(), {**_CALL_PARAMS, "action": "transfer_funds"})


@pytest.mark.parametrize("confidence", [0.98, 0.9700000001, 0.99, 1.0])
def test_confidence_is_bound_exactly(confidence: float) -> None:
    assert not _reused(_cache(), {**_CALL_PARAMS, "confidence": confidence})


def test_a_missing_or_under_confident_call_never_reuses() -> None:
    no_confidence = {k: v for k, v in _CALL_PARAMS.items() if k != "confidence"}
    under_confident = {**_CALL_PARAMS, "confidence": 0.5}

    assert not _reused(_cache(), no_confidence)
    assert not _reused(_cache(), under_confident)
    assert build_routing_verdict_cache(under_confident, verdict="ALLOW") is None


# ---------------------------------------------------------------------------
# gateway_tool_guard re-validates any call the cache does not bind
# ---------------------------------------------------------------------------


class _RecordingClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def validate_action(
        self, *, action: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        self.calls.append(params)
        return {"verdict": GovernanceDecision.ALLOW, "violations": []}


async def _guarded_call(
    monkeypatch: pytest.MonkeyPatch, args: dict[str, Any]
) -> tuple[_RecordingClient, dict[str, Any]]:
    monkeypatch.delenv("CAGE_ROUTING_VERDICT_TTL_S", raising=False)
    client = _RecordingClient()
    monkeypatch.setattr(guard_mod, "GatewayClient", lambda: client)

    async def executor(state: dict[str, Any]) -> dict[str, Any]:
        return {"messages": [ToolMessage(content="EXECUTED", tool_call_id="c1")]}

    call = {"name": "execute_trade_action", "id": "c1", "args": args}
    out = await guard_mod.gateway_tool_guard("execute_trade", approvable=True)(
        executor
    )(
        {
            "messages": [AIMessage(content="", tool_calls=[call])],
            "routing_verdict_cache": build_routing_verdict_cache(
                trade_params(_ORDER), verdict="ALLOW"
            ),
        }
    )
    return client, out


@pytest.mark.asyncio
async def test_tool_guard_reuses_the_verdict_for_the_exact_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, out = await _guarded_call(monkeypatch, dict(_ORDER))

    assert client.calls == []
    assert out["governance_status"] == "ALLOWED"


@pytest.mark.asyncio
@pytest.mark.parametrize(("field", "value"), _EXTRA_FIELDS)
async def test_tool_guard_revalidates_a_call_with_an_extra_field(
    monkeypatch: pytest.MonkeyPatch, field: str, value: Any
) -> None:
    client, out = await _guarded_call(monkeypatch, {**_ORDER, field: value})

    assert len(client.calls) == 1
    assert client.calls[0][field] == value
    assert out["governance_status"] == "ALLOWED"


# ---------------------------------------------------------------------------
# safety_check_node validates every trade step
# ---------------------------------------------------------------------------


@pytest.fixture
def gateway() -> Iterator[Callable[[Handler], list[httpx.Request]]]:
    """Install a MockTransport behind the GatewayClient singleton."""
    GatewayClient._instance = None

    def install(handler: Handler) -> list[httpx.Request]:
        seen: list[httpx.Request] = []

        def recording(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return handler(request)

        client = GatewayClient()
        client._http = httpx.AsyncClient(
            transport=httpx.MockTransport(recording), base_url="http://gateway.test"
        )
        return seen

    yield install
    GatewayClient._instance = None


def _symbol_of(request: httpx.Request) -> str:
    return str(json.loads(request.content)["params"]["symbol"])


def _symbols(seen: list[httpx.Request]) -> list[str]:
    return [_symbol_of(request) for request in seen]


def _by_symbol(answers: dict[str, Handler]) -> Handler:
    return lambda request: answers[_symbol_of(request)](request)


def _allow(signature: str) -> Handler:
    body = {
        "envelope_version": "3.0",
        "envelope_id": f"env-{signature}",
        "signature": signature,
        "payload": {"verdict": "ALLOW", "violations": []},
    }
    return lambda request: httpx.Response(200, json=body)


def _deny(reason: str) -> Handler:
    body = {"verdict": "DENIED", "violations": [reason]}
    return lambda request: httpx.Response(403, json=body)


def _defer(ticket: str) -> Handler:
    body = {"verdict": "DEFER", "defer_id": ticket, "defer_reason": "EXTERNAL_HOLD"}
    return lambda request: httpx.Response(202, json=body)


def _respond(status: int, body: dict[str, Any]) -> Handler:
    return lambda request: httpx.Response(status, json=body)


def _timeout(request: httpx.Request) -> httpx.Response:
    raise httpx.ReadTimeout("gateway too slow", request=request)


def _unreachable(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused", request=request)


def _two_step_state(consecutive_denials: int = 0, **extra: Any) -> dict[str, Any]:
    return {
        "execution_plan_output": _plan(
            _trade("AAA", confidence=0.99), _trade("BBB", confidence=0.99)
        ),
        "consecutive_denials": consecutive_denials,
        **extra,
    }


@pytest.mark.asyncio
async def test_a_denied_second_step_blocks_the_plan_and_counts_a_denial(
    gateway,
) -> None:
    seen = gateway(
        _by_symbol({"AAA": _allow("sig-a"), "BBB": _deny("BBB above limit")})
    )

    out = await safety_check_node(_two_step_state())

    assert out["safety_status"] == "BLOCKED"
    assert out["consecutive_denials"] == 1
    assert out["last_violation"]["reason_code"] == "GOVERNANCE_DENIED"
    assert out["last_violation"]["evidence"].startswith("Trade step 2 of 2: ")
    assert "BBB above limit" in out["last_violation"]["evidence"]
    assert out["routing_verdict_cache"] is None
    assert _symbols(seen) == ["AAA", "BBB"]


@pytest.mark.asyncio
async def test_a_denied_second_step_spends_the_denial_budget(gateway) -> None:
    gateway(_by_symbol({"AAA": _allow("sig-a"), "BBB": _deny("BBB above limit")}))

    out = await safety_check_node(
        _two_step_state(consecutive_denials=MAX_CONSECUTIVE_DENIALS - 1)
    )

    assert out["safety_status"] == "HARD_PAUSE_BUDGET_EXCEEDED"
    assert out["consecutive_denials"] == MAX_CONSECUTIVE_DENIALS


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "second",
    [
        _respond(200, {"verdict": "DENIED", "violations": ["cbf barrier"]}),
        _respond(500, {"detail": "boom"}),
        _respond(401, {"detail": "no workload identity"}),
        _respond(200, {"verdict": "DEFER"}),  # no ticket to park
        _respond(200, {"verdict": "REQUIRE_APPROVAL"}),  # no deferred_id
        _respond(200, {"verdict": "PAUSE"}),
        _respond(200, {"violations": []}),
        _timeout,
        _unreachable,
    ],
    ids=[
        "denied-200",
        "http-500",
        "http-401",
        "defer-without-ticket",
        "approval-without-deferred-id",
        "unknown-verdict",
        "missing-verdict",
        "timeout",
        "unreachable",
    ],
)
async def test_every_fail_closed_second_step_blocks_the_plan(
    gateway, second: Handler
) -> None:
    gateway(_by_symbol({"AAA": _allow("sig-a"), "BBB": second}))

    out = await safety_check_node(_two_step_state())

    assert out["safety_status"] == "BLOCKED"
    assert out["consecutive_denials"] == 1
    assert out["last_violation"]["evidence"].startswith("Trade step 2 of 2: ")
    assert out["routing_verdict_cache"] is None


@pytest.mark.asyncio
async def test_a_refused_first_step_is_not_followed_by_more_requests(
    gateway,
) -> None:
    seen = gateway(_by_symbol({"AAA": _deny("AAA halted"), "BBB": _allow("sig-b")}))

    out = await safety_check_node(_two_step_state())

    assert out["safety_status"] == "BLOCKED"
    assert out["last_violation"]["evidence"].startswith("Trade step 1 of 2: ")
    assert _symbols(seen) == ["AAA"]


@pytest.mark.asyncio
async def test_every_step_allowed_approves_without_caching(gateway) -> None:
    seen = gateway(_by_symbol({"AAA": _allow("sig-a"), "BBB": _allow("sig-b")}))
    state = _two_step_state(consecutive_denials=1)

    out = await safety_check_node(state)

    assert out["safety_status"] == "APPROVED"
    assert out["consecutive_denials"] == 0
    assert out["last_violation"] is None
    assert out["routing_verdict_cache"] is None
    assert out["governance_signature"] == "sig-a,sig-b"
    assert [json.loads(r.content)["params"] for r in seen] == extract_trade_steps(
        state["execution_plan_output"]
    )


@pytest.mark.asyncio
async def test_a_single_step_allow_is_still_cached(gateway) -> None:
    gateway(_allow("sig-a"))

    out = await safety_check_node(
        {"execution_plan_output": _plan(_trade("AAA", confidence=0.99))}
    )

    assert out["safety_status"] == "APPROVED"
    assert out["routing_verdict_cache"] is not None
    assert out["governance_signature"] == "sig-a"


@pytest.mark.asyncio
async def test_a_fresh_cache_is_not_reused_for_a_multi_step_plan(gateway) -> None:
    seen = gateway(_by_symbol({"AAA": _allow("sig-a"), "BBB": _allow("sig-b")}))
    state = _two_step_state()
    first = extract_trade_steps(state["execution_plan_output"])[0]
    state["routing_verdict_cache"] = build_routing_verdict_cache(first, verdict="ALLOW")
    assert reusable_allow_verdict(state["routing_verdict_cache"], first) is not None

    out = await safety_check_node(state)

    assert out["safety_status"] == "APPROVED"
    assert _symbols(seen) == ["AAA", "BBB"]
    assert out["routing_verdict_cache"] is None


@pytest.mark.asyncio
async def test_a_deferred_step_defers_the_plan(gateway) -> None:
    gateway(_by_symbol({"AAA": _allow("sig-a"), "BBB": _defer("ticket-b")}))

    out = await safety_check_node(_two_step_state(consecutive_denials=1))

    assert out["safety_status"] == "DEFERRED"
    assert out["deferral_ticket_id"] == "ticket-b"
    assert out["deferral_reason"] == "EXTERNAL_HOLD"
    assert "consecutive_denials" not in out  # deferral is not approval
    assert out["routing_verdict_cache"] is None


@pytest.mark.asyncio
async def test_a_refusal_after_a_deferral_still_blocks(gateway) -> None:
    seen = gateway(
        _by_symbol({"AAA": _defer("ticket-a"), "BBB": _deny("BBB above limit")})
    )

    out = await safety_check_node(_two_step_state())

    assert out["safety_status"] == "BLOCKED"
    assert out["consecutive_denials"] == 1
    assert _symbols(seen) == ["AAA", "BBB"]


@pytest.mark.asyncio
async def test_the_first_deferral_ticket_is_parked(gateway) -> None:
    gateway(_by_symbol({"AAA": _defer("ticket-a"), "BBB": _defer("ticket-b")}))

    out = await safety_check_node(_two_step_state())

    assert out["safety_status"] == "DEFERRED"
    assert out["deferral_ticket_id"] == "ticket-a"


@pytest.mark.asyncio
async def test_a_step_requiring_approval_proceeds_with_its_deferred_id(
    gateway,
) -> None:
    approval = {"verdict": "REQUIRE_APPROVAL", "deferred_id": "d-b", "violations": []}
    gateway(_by_symbol({"AAA": _allow("sig-a"), "BBB": _respond(200, approval)}))

    out = await safety_check_node(_two_step_state(consecutive_denials=1))

    assert out["safety_status"] == "APPROVED"
    assert out["consecutive_denials"] == 0
    assert out["deferred_id"] == "d-b"
    assert out["routing_verdict_cache"] is None


@pytest.mark.asyncio
async def test_substring_steps_never_reach_the_gateway_or_the_denial_budget(
    gateway,
) -> None:
    seen = gateway(_allow("sig-a"))
    survey_steps = [_step(name) for name in _SUBSTRING_NAMES[:3]]

    skipped = await safety_check_node(
        {"execution_plan_output": _plan(*survey_steps), "consecutive_denials": 1}
    )
    approved = await safety_check_node(
        {
            "execution_plan_output": _plan(*survey_steps, _trade("AAA")),
            "consecutive_denials": 1,
        }
    )

    assert skipped == {"safety_status": "SKIPPED", "routing_verdict_cache": None}
    assert approved["safety_status"] == "APPROVED"
    assert approved["consecutive_denials"] == 0
    assert _symbols(seen) == ["AAA"]


@pytest.mark.asyncio
async def test_a_malformed_confidence_in_any_step_blocks_without_asking(
    gateway,
) -> None:
    seen = gateway(_allow("sig-a"))
    plan = _plan(_trade("AAA", confidence=0.99), _trade("BBB", confidence=True))

    out = await safety_check_node(
        {"execution_plan_output": plan, "consecutive_denials": 0}
    )

    assert out["safety_status"] == "BLOCKED"
    assert out["consecutive_denials"] == 1
    assert out["last_violation"]["reason_code"] == "GATEWAY_ERROR"
    assert "confidence" in out["last_violation"]["evidence"]
    assert seen == []


@pytest.mark.asyncio
async def test_a_missing_confidence_is_submitted_as_zero_and_not_cached(
    gateway,
) -> None:
    seen = gateway(_allow("sig-a"))

    out = await safety_check_node({"execution_plan_output": _plan(_trade("AAA"))})

    assert json.loads(seen[0].content)["params"]["confidence"] == 0.0
    assert out["safety_status"] == "APPROVED"
    assert out["routing_verdict_cache"] is None


# ---------------------------------------------------------------------------
# evaluator_node dry-runs every trade step
# ---------------------------------------------------------------------------


def _install_dry_run(
    monkeypatch: pytest.MonkeyPatch, verdicts: dict[str, str]
) -> list[tuple[str, dict[str, Any]]]:
    calls: list[tuple[str, dict[str, Any]]] = []

    async def fake(
        target_tool: str, target_params: dict[str, Any], risk_profile: str = "Medium"
    ) -> dict[str, Any]:
        calls.append((target_tool, target_params))
        symbol = str(target_params.get("symbol", ""))
        verdict = verdicts[symbol]
        return {
            "verdict": verdict,
            "message": f"{symbol} {verdict}",
            "opa_results": {"symbol": symbol},
        }

    monkeypatch.setattr(evaluator_mod, "simulate_governance_check", fake)
    return calls


@pytest.mark.asyncio
async def test_evaluator_dry_runs_every_trade_step(monkeypatch) -> None:
    calls = _install_dry_run(monkeypatch, {"AAA": "ALLOW", "BBB": "ALLOW"})
    plan = _plan(_trade("AAA", confidence=0.99), _trade("BBB", confidence=0.99))

    out = await evaluator_mod.evaluator_node({"execution_plan_output": plan})

    assert calls == [(TRADE_ACTION, p) for p in extract_trade_steps(plan)]
    assert out["risk_status"] == "APPROVED"
    assert out["routing_verdict_cache"] is None


@pytest.mark.asyncio
async def test_evaluator_rejects_a_plan_with_any_refused_step(monkeypatch) -> None:
    calls = _install_dry_run(monkeypatch, {"AAA": "ALLOW", "BBB": "DENY"})
    plan = _plan(_trade("AAA", confidence=0.99), _trade("BBB", confidence=0.99))

    out = await evaluator_mod.evaluator_node({"execution_plan_output": plan})

    assert len(calls) == 2
    assert out["risk_status"] == "REJECTED_REVISE"
    assert out["evaluation_result"]["verdict"] == "REJECTED"
    assert "Trade step 2: BBB DENY" in out["risk_feedback"]
    assert out["opa_results"] == {"symbol": "BBB"}
    assert out["routing_verdict_cache"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("verdicts", "approved", "needs_approval"),
    [
        ({"AAA": "ALLOW", "BBB": "REQUIRE_APPROVAL"}, True, True),
        ({"AAA": "REQUIRE_APPROVAL", "BBB": "DENY"}, False, False),
        ({"AAA": "NARROW", "BBB": "DEFER"}, False, False),
    ],
)
async def test_evaluator_aggregates_step_verdicts(
    monkeypatch, verdicts: dict[str, str], approved: bool, needs_approval: bool
) -> None:
    _install_dry_run(monkeypatch, verdicts)
    plan = _plan(_trade("AAA", confidence=0.99), _trade("BBB", confidence=0.99))

    out = await evaluator_mod.evaluator_node({"execution_plan_output": plan})

    assert out["risk_status"] == ("APPROVED" if approved else "REJECTED_REVISE")
    assert out["evaluation_result"]["requires_approval"] is needs_approval


@pytest.mark.asyncio
async def test_evaluator_caches_only_a_confident_single_step_allow(
    monkeypatch,
) -> None:
    calls = _install_dry_run(monkeypatch, {"AAA": "ALLOW"})

    confident = await evaluator_mod.evaluator_node(
        {"execution_plan_output": _plan(_trade("AAA", confidence=0.99))}
    )
    silent = await evaluator_mod.evaluator_node(
        {"execution_plan_output": _plan(_trade("AAA"))}
    )

    assert confident["routing_verdict_cache"] is not None
    assert calls[1][1]["confidence"] == 0.0
    assert silent["risk_status"] == "APPROVED"
    assert silent["routing_verdict_cache"] is None


@pytest.mark.asyncio
async def test_evaluator_sends_back_an_invalid_confidence_without_a_dry_run(
    monkeypatch,
) -> None:
    calls = _install_dry_run(monkeypatch, {"AAA": "ALLOW"})

    out = await evaluator_mod.evaluator_node(
        {"execution_plan_output": _plan(_trade("AAA", confidence="high"))}
    )

    assert calls == []
    assert out["risk_status"] == "REJECTED_REVISE"
    assert "confidence" in out["risk_feedback"]


@pytest.mark.asyncio
async def test_evaluator_does_not_preview_substring_steps_as_trades(
    monkeypatch,
) -> None:
    calls = _install_dry_run(monkeypatch, {"": "ALLOW"})

    out = await evaluator_mod.evaluator_node(
        {"execution_plan_output": _plan(_step("buyer_survey"))}
    )

    assert calls == [("market_analysis", {})]
    assert out["risk_status"] == "APPROVED"
