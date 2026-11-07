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

"""Advisor graph -> gateway previews -> trade tool, end to end (POAM-2026-105).

The advisor's two previews (``safety_check_node`` and the
``gateway_tool_guard`` around the trader) ask the real gateway app over ASGI
at ``/governance/validate-action``. The trade tool then runs the single
committing pass with the same governor. Before the server-input seam, the
previews evaluated whatever STPA inputs the caller sent. The advisor sent
none, so UCA-2 / UCA-5 (and UCA-13 on sells) refused every trade before it
reached the tool. The evaluator only passed because it injected 0.0 defaults.

Now both paths bind the finance plugin's server-side inputs (quote age,
NAV drawdown, current NAV) through ``PluginContribution.server_inputs``:

* a normal buy clears both previews and executes once, in every region;
* caller values for those keys are ignored, both out-of-limit and
  falsely in-limit ones;
* a faulted source refuses the trade in the preview, with a refusal receipt,
  and the committing tool refuses it as well, with nothing actuated.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from langchain_core.messages import AIMessage, ToolMessage

from src.cage_finance.stpa import uca_rules
from src.cage_finance.tools.tool_provider import execute_trade_action
from src.gateway.governance import jwks as jwks_mod
from src.gateway.governance import kms_signer as kms_signer_mod
from src.gateway.governance.contracts import NormBinding
from src.gateway.governance.defer_queue import DeferQueue, DeferReason
from src.gateway.governance.ftra import classifier as ftra_classifier_mod
from src.gateway.governance.ftra.classifier import registry_digest
from src.gateway.governance.governance_envelope import GovernanceEnvelopeBuilder
from src.gateway.governance.governor.governor import SymbolicGovernor
from src.gateway.governance.governor.stages.warrant import WarrantStage
from src.gateway.governance.jwks import JWKSet, pem_to_jwk
from src.gateway.governance.schemas.thresholds import load_and_validate_thresholds
from src.gateway.governance.seams.ground_truth import FaultMode
from src.gateway.governance.warrant.cache import WarrantCache
from src.gateway.server.governance_middleware import governance_app
from src.gateway.server.workload_identity import CLIENT_IDENTITY_HEADER, _serving
from src.governed_financial_advisor.graph.governance.tool_guard import (
    gateway_tool_guard,
)
from src.governed_financial_advisor.graph.graph import _build_workflow
from src.governed_financial_advisor.graph.nodes.defer_node import defer_node
from src.governed_financial_advisor.graph.nodes.safety_node import (
    MAX_CONSECUTIVE_DENIALS,
    route_safety,
    safety_check_node,
)
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient
from tests.fixtures.governor import (
    WARRANT_TEST_GOVERNING_VERSION,
    WARRANT_TEST_NOW,
    StaticWarrantSource,
)
from tests.test_trade_governance_e2e import (  # noqa: F401  (gw is a fixture)
    ADVISOR,
    JUNIOR_DESK,
    Gateway,
    gw,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

_UCA_2 = "STPA_UCA_UCA_2"
_UCA_5 = "STPA_UCA_UCA_5"
_UCA_13 = "STPA_UCA_UCA_13"
#: region -> UCA-5 max daily drawdown (%)
_DRAWDOWN_LIMIT = {"US_FED": 4.5, "APAC_MAS": 4.0, "EU_ECB": 3.5}
_TOOL_KWARGS = frozenset(inspect.signature(execute_trade_action).parameters)


@pytest.fixture(params=tuple(_DRAWDOWN_LIMIT))
def region(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Pin the generated finance rules to ``region``'s effective thresholds."""
    name: str = request.param
    monkeypatch.setattr(
        uca_rules, "THRESHOLDS", load_and_validate_thresholds(region=name)
    )
    return name


@pytest.fixture
async def advisor(gw: Gateway) -> AsyncIterator[Gateway]:  # noqa: F811
    """Route the advisor's ``GatewayClient`` singleton to the gateway app."""
    GatewayClient._instance = None
    gw.http.headers[CLIENT_IDENTITY_HEADER] = ADVISOR  # mesh workload identity
    GatewayClient()._http = gw.http
    yield gw
    GatewayClient._instance = None


def _plan(side: str = "buy", amount: float = 500.0) -> dict[str, Any]:
    return {
        "action": "execute_trade",
        "symbol": "AAPL",
        "amount": amount,
        "currency": "USD",
        "confidence": 0.99,
        "side": side,
    }


def _tool_call(side: str = "buy", **extra: Any) -> dict[str, Any]:
    return {
        "name": "execute_trade_action",
        "id": "call-1",
        "args": {
            "symbol": "AAPL",
            "amount": 500.0,
            "currency": "USD",
            "confidence": 0.99,
            "side": side,
            **extra,
        },
    }


def _trader(gateway: Gateway, results: list[str]) -> Any:
    """The governed trader: the trade tool's committing run, per tool call.

    The live node calls the tool over MCP; arguments the tool does not accept
    are rejected there, so they are dropped here too. The MCP request carries
    the advisor's verified identity (WorkloadIdentityMiddleware).
    """

    async def node(state: dict[str, Any]) -> dict[str, Any]:
        messages = []
        for call in state["messages"][-1].tool_calls:
            kwargs = {k: v for k, v in call["args"].items() if k in _TOOL_KWARGS}
            with _serving(ADVISOR):
                result = await execute_trade_action(
                    **kwargs,
                    deferred_id=state.get("deferred_id"),
                    governor=gateway.governor,
                )
            results.append(result)
            messages.append(ToolMessage(content=result, tool_call_id=call["id"]))
        return {"messages": messages}

    return node


async def _run_trader(gateway: Gateway, call: dict[str, Any]) -> tuple[dict, list[str]]:
    results: list[str] = []
    guarded = gateway_tool_guard("execute_trade", approvable=True)(
        _trader(gateway, results)
    )
    out = await guarded({"messages": [AIMessage(content="", tool_calls=[call])]})
    return out, results


def _refused_codes(gateway: Gateway) -> str:
    return " ".join(
        f"{c.kwargs.get('refusal_reason')} {c.kwargs.get('receipt')}"
        for c in gateway.refusals.await_args_list
    )


# ---------------------------------------------------------------------------
# A normal buy reaches and clears the trade tool, in every region
# ---------------------------------------------------------------------------


async def test_normal_buy_clears_both_previews_and_executes_once(
    advisor: Gateway, region: str
) -> None:
    safety = await safety_check_node({"execution_plan_output": _plan()})
    assert safety["safety_status"] == "APPROVED", safety

    out, results = await _run_trader(advisor, _tool_call())

    assert out["governance_status"] != "DENIED", out
    assert len(results) == 1 and results[0].startswith("EXECUTED"), results
    advisor.actuate.assert_awaited_once()
    advisor.refusals.assert_not_awaited()


async def test_normal_sell_clears_both_previews_and_executes_once(
    advisor: Gateway, region: str
) -> None:
    safety = await safety_check_node({"execution_plan_output": _plan(side="sell")})
    assert safety["safety_status"] == "APPROVED", safety

    out, results = await _run_trader(advisor, _tool_call(side="sell"))

    assert len(results) == 1 and results[0].startswith("EXECUTED"), (out, results)
    advisor.actuate.assert_awaited_once()


# ---------------------------------------------------------------------------
# Caller-supplied STPA inputs are never read
# ---------------------------------------------------------------------------


async def test_out_of_limit_caller_inputs_do_not_refuse_the_preview(
    advisor: Gateway,
) -> None:
    call = _tool_call(
        latency_ms=10_000.0, drawdown=99.0, current_drawdown=0.99, portfolio_total=1.0
    )

    out, results = await _run_trader(advisor, call)

    assert len(results) == 1 and results[0].startswith("EXECUTED"), (out, results)
    advisor.refusals.assert_not_awaited()


async def test_in_limit_caller_inputs_do_not_mask_a_server_breach(
    advisor: Gateway, region: str
) -> None:
    # The NAV source reports a drawdown just over the region's limit; the
    # caller claims a flat book and a fresh quote, under every alias.
    advisor.nav_source.set_drawdown_pct(_DRAWDOWN_LIMIT[region] + 0.25)
    call = _tool_call(
        latency_ms=0.0, drawdown=0.0, portfolio_drawdown_pct=0.0, current_drawdown=0.0
    )

    out, results = await _run_trader(advisor, call)

    assert results == [], "the preview must refuse before the tool runs"
    assert out["governance_status"] == "DENIED", out
    assert _UCA_5 in _refused_codes(advisor)
    advisor.actuate.assert_not_awaited()


async def test_the_regional_drawdown_floor_binds_the_preview(
    advisor: Gateway, region: str
) -> None:
    # 4.25 % is inside the US limit (4.5) but outside APAC (4.0) and EU (3.5).
    advisor.nav_source.set_drawdown_pct(4.25)

    safety = await safety_check_node({"execution_plan_output": _plan()})

    expected = "APPROVED" if region == "US_FED" else "BLOCKED"
    assert safety["safety_status"] == expected, safety


# ---------------------------------------------------------------------------
# Faulted sources: refused in the preview with evidence, and at commit
# ---------------------------------------------------------------------------


async def _assert_refused_everywhere(
    gateway: Gateway, codes: tuple[str, ...], side: str = "buy"
) -> None:
    safety = await safety_check_node({"execution_plan_output": _plan(side=side)})
    assert safety["safety_status"] == "BLOCKED", safety
    for code in codes:
        assert code in safety["last_violation"]["evidence"], safety

    # Refusal receipt for the preview (validate-action).
    gateway.refusals.assert_awaited()
    assert all(
        c.kwargs.get("action_id") == "execute_trade"
        for c in gateway.refusals.await_args_list
    )
    assert codes[0] in _refused_codes(gateway)

    # The committing tool, called directly (no preview), refuses too.
    gateway.refusals.reset_mock()
    with _serving(ADVISOR):
        result = await execute_trade_action(
            "AAPL",
            500.0,
            "USD",
            0.99,
            str(uuid.uuid4()),
            side=side,
            governor=gateway.governor,
        )
    assert result.startswith("BLOCKED"), result
    assert codes[0] in _refused_codes(gateway)
    gateway.actuate.assert_not_awaited()
    assert await gateway.seal_redis.dbsize() == 0


@pytest.mark.parametrize("fault", [FaultMode.TIMEOUT, FaultMode.STALE_TIMESTAMP])
async def test_market_feed_fault_refuses_with_uca_2(
    advisor: Gateway, region: str, fault: FaultMode
) -> None:
    advisor.market_feed.inject_fault(fault)
    await _assert_refused_everywhere(advisor, (_UCA_2,))


async def test_nav_fault_refuses_a_buy_with_uca_5(
    advisor: Gateway, region: str
) -> None:
    advisor.nav_source.inject_fault(FaultMode.CONNECTION_ERROR)
    await _assert_refused_everywhere(advisor, (_UCA_5,))


async def test_nav_fault_refuses_a_sell_with_uca_5_and_uca_13(
    advisor: Gateway,
) -> None:
    advisor.nav_source.inject_fault(FaultMode.NAN_VALUE)
    await _assert_refused_everywhere(advisor, (_UCA_5, _UCA_13), side="sell")
    # The committing run's receipt records the bound params: no NAV-derived
    # input was resolved, and none was taken from the caller.
    (receipt,) = advisor.refusals.await_args_list
    assert not {"drawdown", "portfolio_total"} & set(receipt.kwargs["params"])


async def test_the_regional_volume_fraction_binds_the_preview(
    advisor: Gateway, region: str
) -> None:
    # 70 shares (~$7,000 at ~$100) of a 10,000-share average day is 0.7 %:
    # inside US_FED (1 %) and APAC_MAS (0.8 %), outside EU_ECB (0.5 %).
    advisor.market_feed.set_daily_volume(10_000.0)

    safety = await safety_check_node({"execution_plan_output": _plan(amount=7_000.0)})

    if region == "EU_ECB":
        assert safety["safety_status"] == "BLOCKED", safety
        assert "STPA_UCA_UCA_6" in safety["last_violation"]["evidence"]
    else:
        assert safety["safety_status"] == "APPROVED", safety


async def test_daily_volume_fault_refuses_with_uca_6(
    advisor: Gateway, region: str
) -> None:
    advisor.market_feed.inject_volume_fault(FaultMode.STALE_TIMESTAMP)
    await _assert_refused_everywhere(advisor, ("STPA_UCA_UCA_6",))


async def test_a_tool_call_claiming_senior_is_routed_as_junior(
    advisor: Gateway,
) -> None:
    # GHSA-w39v-5v7h-fxg9: a prompt-injected tool call claims senior for
    # $6,000 from an advisor workload with no senior binding. The guard's
    # preview is evaluated as junior (MANUAL_REVIEW), so the call parks for a
    # human and the trade tool never runs.
    advisor.http.headers[CLIENT_IDENTITY_HEADER] = JUNIOR_DESK
    call = _tool_call(amount=6_000.0, trader_role="senior", trader_id="trader-7")

    out, results = await _run_trader(advisor, call)

    assert out["governance_status"] == "REQUIRE_APPROVAL"
    assert out["deferred_id"]
    assert results == []
    (evaluated,) = advisor.policy.calls
    assert (evaluated["trader_role"], evaluated["trader_id"]) == ("junior", JUNIOR_DESK)
    advisor.actuate.assert_not_awaited()


# ---------------------------------------------------------------------------
# DEFER wire contract & LangGraphHarness.tla conformance over real ASGITransport
# ---------------------------------------------------------------------------


class _AsymmetricTestSigner:
    """Real ECDSA P-256 (ES256) signer registered in an out-of-band JWKSet."""

    is_kms_active = True
    kms_active = True

    def __init__(self) -> None:
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        pem_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.jwks = JWKSet()
        self.kid = self.jwks.add_key(pem_bytes)
        jwk = dict(pem_to_jwk(pem_bytes, kid=self.kid))
        jwk["alg"] = "ES256"
        self.public_jwk = jwk

    async def sign_precomputed_digest_async(self, digest: bytes) -> str:
        sig_der = self._private_key.sign(
            digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
        return sig_der.hex()


def _install_es256_signer(monkeypatch: pytest.MonkeyPatch) -> _AsymmetricTestSigner:
    signer = _AsymmetricTestSigner()
    monkeypatch.setattr(kms_signer_mod, "get_governance_signer", lambda: signer)
    monkeypatch.setattr(jwks_mod, "get_jwks", lambda: signer.jwks)
    return signer


def _install_reversible_trade_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Install a digest-verified FTRA registry classifying ``execute_trade`` as REVERSIBLE.

    With ``execute_trade`` reversible, low confidence (< 0.70) isolates
    ``ConfidenceStage``'s ``ViolationKind.DEFERRABLE`` (``CONFIDENCE_BELOW_THRESHOLD``)
    without FTRA's irreversible-terminal ``ViolationKind.HITL`` outranking it.
    """
    base_doc = json.loads(
        Path("config/ftra/terminal_registry.json").read_text(encoding="utf-8")
    )
    base_doc["terminals"]["execute_trade"] = "REVERSIBLE"
    base_doc["autonomous_envelope"].pop("execute_trade", None)
    base_doc["manifest_sha256"] = registry_digest(base_doc)
    reg_path = tmp_path / "terminal_registry.json"
    reg_path.write_text(json.dumps(base_doc), encoding="utf-8")
    monkeypatch.setattr(ftra_classifier_mod, "_active_registry_path", lambda: reg_path)
    return reg_path


def _graph_route_after_safety() -> Any:
    """Extract the live ``route_after_safety`` closure from ``graph._build_workflow()``."""
    workflow = _build_workflow()
    return workflow.branches["safety_check"]["route_after_safety"].path.func


async def test_low_confidence_defer_flows_through_safety_and_defer_node_e2e(
    advisor: Gateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Low confidence (< 0.70) produces a signed HTTP 200 DEFER envelope with ``defer_token``
    over real ASGITransport and terminates cleanly in ``defer_node`` without ``checkpoint_payload``.
    """
    _install_reversible_trade_registry(tmp_path, monkeypatch)
    signer = _install_es256_signer(monkeypatch)

    wire_responses: list[httpx.Response] = []

    async def _capture_response(response: httpx.Response) -> None:
        await response.aread()
        wire_responses.append(response)

    advisor.http.event_hooks["response"].append(_capture_response)

    plan = {**_plan(amount=500.0), "confidence": 0.55}
    initial_state: dict[str, Any] = {
        "consecutive_denials": 0,
        "execution_plan_output": plan,
    }

    safety_out = await safety_check_node(initial_state)

    # 1. Verify the real HTTP 200 signed v3.0 GovernanceEnvelope on the wire via out-of-band kid.
    assert len(wire_responses) == 1
    wire_resp = wire_responses[0]
    assert wire_resp.status_code == 200
    raw_envelope = wire_resp.json()
    assert raw_envelope["envelope_version"] == "3.0"
    assert raw_envelope["signature"]["algorithm"] == "ES256"
    assert raw_envelope["signature"]["kid"] == signer.kid
    assert GovernanceEnvelopeBuilder().verify(raw_envelope) is True

    payload = raw_envelope["payload"]
    assert payload["verdict"] == "DEFER"
    assert "defer_id" not in payload
    defer_token = payload["defer_token"]
    assert isinstance(defer_token, str) and defer_token.strip()
    assert payload["defer_reason"] == DeferReason.CONFIDENCE_BELOW_THRESHOLD.value

    # 2. Verify safety_check_node state output and deterministic routing.
    assert safety_out["safety_status"] == "DEFERRED"
    assert safety_out["deferral_ticket_id"] == defer_token
    assert safety_out["deferral_reason"] == DeferReason.CONFIDENCE_BELOW_THRESHOLD.value
    assert "consecutive_denials" not in safety_out

    after_safety = {**initial_state, **safety_out}
    assert route_safety(after_safety) == "defer_node"
    assert _graph_route_after_safety()(after_safety) == "defer_node"

    # 3. Verify defer_node turn-terminal hold output (no checkpoint_payload).
    defer_out = await defer_node(after_safety)
    assert defer_out["safety_status"] == "DEFERRED"
    assert defer_out["deferral_ticket_id"] == defer_token
    assert defer_out["next_step"] == "FINISH"
    assert "checkpoint_payload" not in defer_out
    msg = defer_out["messages"][0].content
    assert "turn-terminal governance hold" in msg
    assert defer_token in msg
    assert "CONFIDENCE_BELOW_THRESHOLD" in msg
    assert "resume automatically" not in msg
    assert "approved by a human reviewer" not in msg

    # 4. Verify real DeferQueue record in fakeredis is PARKED with CONFIDENCE_BELOW_THRESHOLD.
    queue = DeferQueue(advisor.defer_redis)
    assert await advisor.defer_redis.hget(f"DEFER:{defer_token}", "status") == "PARKED"
    parked_token = await queue.get_token(defer_token)
    assert parked_token is not None
    assert parked_token.defer_id == defer_token
    assert parked_token.defer_reason == DeferReason.CONFIDENCE_BELOW_THRESHOLD
    advisor.actuate.assert_not_awaited()
    advisor.refusals.assert_not_awaited()


async def test_warrant_ineligible_defer_flows_through_safety_and_defer_node_e2e(
    advisor: Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Missing standing warrant on unmodified IRREVERSIBLE_TERMINAL registry yields
    a signed HTTP 200 DEFER (``WARRANT_INELIGIBLE``) and warrant-specific hold text.
    """
    _install_es256_signer(monkeypatch)

    warrant_stage = WarrantStage(
        bindings=(
            NormBinding(
                norm_id="confidence.min_trade_confidence",
                governing_version=WARRANT_TEST_GOVERNING_VERSION,
                actions=frozenset({"execute_trade"}),
                requires_warrant=True,
                value=0.95,
            ),
        ),
        cache=WarrantCache(StaticWarrantSource({})),
        jurisdiction="EU_ECB",
        clock=lambda: WARRANT_TEST_NOW,
    )
    warranted_components = dataclasses.replace(
        advisor.governor._components,
        core_stages=(*advisor.governor._components.core_stages, warrant_stage),
    )
    governance_app.state.governor = SymbolicGovernor(warranted_components)

    initial_state: dict[str, Any] = {
        "consecutive_denials": 0,
        "execution_plan_output": _plan(amount=500.0),
    }
    safety_out = await safety_check_node(initial_state)

    assert safety_out["safety_status"] == "DEFERRED"
    defer_token = safety_out["deferral_ticket_id"]
    assert defer_token
    assert safety_out["deferral_reason"] == DeferReason.WARRANT_INELIGIBLE.value

    after_safety = {**initial_state, **safety_out}
    assert _graph_route_after_safety()(after_safety) == "defer_node"

    defer_out = await defer_node(after_safety)
    assert "checkpoint_payload" not in defer_out
    msg = defer_out["messages"][0].content
    assert "WARRANT_INELIGIBLE" in msg
    assert "external reliance or warrant precondition" in msg
    assert "cannot be overridden by human approval" in msg
    assert "resume automatically" not in msg

    queue = DeferQueue(advisor.defer_redis)
    assert await advisor.defer_redis.hget(f"DEFER:{defer_token}", "status") == "PARKED"
    parked_token = await queue.get_token(defer_token)
    assert parked_token is not None
    assert parked_token.defer_reason == DeferReason.WARRANT_INELIGIBLE


async def test_consecutive_denials_conformance_across_deny_defer_deny_e2e(
    advisor: Gateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Conforms with LangGraphHarness.tla:348-371 (SafetyDefer / SafetyDeny) over ASGITransport:
    Turn 1 DENY (0 -> 1, BLOCKED) -> Turn 2 DEFER (remains 1, DEFERRED) ->
    Turn 3 DENY (1 -> 2, HARD_PAUSE_BUDGET_EXCEEDED).
    """
    _install_reversible_trade_registry(tmp_path, monkeypatch)
    _install_es256_signer(monkeypatch)
    route_after_safety = _graph_route_after_safety()

    state: dict[str, Any] = {"consecutive_denials": 0}

    # Turn 1: DENY (amount exceeds senior OPA and cash barrier limits -> HTTP 403).
    state["execution_plan_output"] = _plan(amount=2_000_000.0)
    turn1 = await safety_check_node(state)
    assert turn1["safety_status"] == "BLOCKED"
    assert turn1["consecutive_denials"] == 1
    state.update(turn1)
    assert route_safety(state) == "explainer"
    assert route_after_safety(state) == "explainer"

    # Turn 2: real gateway DEFER (low confidence 0.55 < 0.70 -> HTTP 200 DEFER).
    # Must NOT fall through to _blocked or increment consecutive_denials to 2.
    state["execution_plan_output"] = {**_plan(amount=500.0), "confidence": 0.55}
    turn2 = await safety_check_node(state)
    assert turn2["safety_status"] == "DEFERRED"
    assert "consecutive_denials" not in turn2
    state.update(turn2)
    assert state["consecutive_denials"] == 1
    assert route_safety(state) == "defer_node"
    assert route_after_safety(state) == "defer_node"

    turn2_defer = await defer_node(state)
    assert turn2_defer["safety_status"] == "DEFERRED"
    assert "checkpoint_payload" not in turn2_defer
    state.update(turn2_defer)
    assert state["consecutive_denials"] == 1

    # Turn 3: second DENY exhausts MAX_CONSECUTIVE_DENIALS (1 -> 2 -> HARD_PAUSE_BUDGET_EXCEEDED).
    state["execution_plan_output"] = _plan(amount=2_000_000.0)
    turn3 = await safety_check_node(state)
    assert turn3["consecutive_denials"] == MAX_CONSECUTIVE_DENIALS == 2
    assert turn3["safety_status"] == "HARD_PAUSE_BUDGET_EXCEEDED"
    state.update(turn3)
    assert route_safety(state) == "human_review"
    advisor.actuate.assert_not_awaited()
