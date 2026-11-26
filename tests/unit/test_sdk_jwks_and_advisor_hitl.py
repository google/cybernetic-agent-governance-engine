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

"""Hermetic regression suite for SDK-02 (JWKS revocation & outage cooldown) and DOMADV-05 (advisor HITL lifecycle)."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import importlib
import json
import time
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Annotated, Any, TypedDict
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jwt as pyjwt
import pytest
from cage_client import CageClient, JwksKeyResolver, RoutingSealVerificationError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.types import Command

from src.gateway.governance.commit_outcome import CommitOutcome, CommitStatus
from src.governed_financial_advisor.graph.checkpointer import CheckpointDurabilityError
from src.governed_financial_advisor.graph.nodes.agent_nodes import governed_trader_node
from src.governed_financial_advisor.graph.nodes.approval_node import (
    create_approval_node,
    rejection_node,
)
from src.governed_financial_advisor.graph.nodes.safety_node import safety_check_node
from src.governed_financial_advisor.graph.state import AgentState
from src.governed_financial_advisor.graph.subgraphs.governed_trader_graph import (
    build_governed_trader_graph,
    drift_blocked_node,
    guarded_tool_executor_node,
    post_hitl_rehydrate_node,
    post_hitl_revalidate_node,
)
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient
from src.governed_financial_advisor.utils.context import user_context
from tests.fixtures.signed_gateway import SignedGatewayStub

pytestmark = [pytest.mark.unit, pytest.mark.local]

_SERVICE_KEY = "test-hitl-service-api-key"
_ISSUER = "https://idp.hitl.example"
_AUDIENCE = "cage-advisor"
_KID = "oidc-k1"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _ec_jwk(kid: str = "gw-ec-01") -> tuple[ec.EllipticCurvePrivateKey, dict[str, Any]]:
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    return priv, {
        "kty": "EC",
        "crv": "P-256",
        "kid": kid,
        "use": "sig",
        "alg": "ES256",
        "x": _b64u(nums.x.to_bytes(32, "big")),
        "y": _b64u(nums.y.to_bytes(32, "big")),
    }


def _rsa_jwk(kid: str = "gw-rsa-bad") -> dict[str, Any]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = priv.public_key().public_numbers()
    n_len = (nums.n.bit_length() + 7) // 8
    e_len = (nums.e.bit_length() + 7) // 8
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _b64u(nums.n.to_bytes(n_len, "big")),
        "e": _b64u(nums.e.to_bytes(e_len, "big")),
    }


@pytest.fixture
def gateway() -> Iterator[
    Callable[[Callable[[httpx.Request], httpx.Response]], list[httpx.Request]]
]:
    """Install a SignedGatewayStub MockTransport behind GatewayClient singleton."""
    GatewayClient._instance = None
    stub = SignedGatewayStub()

    def install(
        handler: Callable[[httpx.Request], httpx.Response],
    ) -> list[httpx.Request]:
        seen: list[httpx.Request] = []

        def recording(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return handler(req)

        client = GatewayClient()
        client._http = httpx.AsyncClient(
            transport=httpx.MockTransport(stub.transport_handler(recording)),
            base_url="http://gateway.test",
        )
        return seen

    yield install
    GatewayClient._instance = None


@pytest.fixture(scope="module")
def advisor_server() -> Any:
    stubs = (
        ("src.integrations.nemo.manager", "load_rails", {"return_value": MagicMock()}),
        ("src.gateway.infrastructure.telemetry_client", "configure_telemetry", {}),
        (
            "opentelemetry.instrumentation.langchain",
            "LangchainInstrumentor.instrument",
            {},
        ),
    )
    with contextlib.ExitStack() as stack:
        for module_name, attr, kwargs in stubs:
            try:
                importlib.import_module(module_name)
            except ImportError:
                continue
            stack.enter_context(patch(f"{module_name}.{attr}", **kwargs))
        import src.governed_financial_advisor.server as srv
    return srv


@pytest.fixture
def mint_user_jwt(monkeypatch: pytest.MonkeyPatch) -> Callable[[str], str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "x": _b64u(nums.x.to_bytes(32, "big")),
                "y": _b64u(nums.y.to_bytes(32, "big")),
                "kid": _KID,
                "alg": "ES256",
            }
        ]
    }
    monkeypatch.setenv("CAGE_ENV", "production")
    monkeypatch.setenv("CAGE_API_KEY", _SERVICE_KEY)
    monkeypatch.setenv("CAGE_USER_OIDC_ISSUER", _ISSUER)
    monkeypatch.setenv("CAGE_USER_OIDC_AUDIENCE", _AUDIENCE)
    monkeypatch.setenv("CAGE_USER_OIDC_JWKS_JSON", json.dumps(jwks))
    for var in (
        "CAGE_USER_OIDC_TRUST_ANCHORS_FILE",
        "CAGE_ALLOW_ASSERTED_PRINCIPAL",
        "CAGE_REQUIRE_VERIFIED_PRINCIPAL",
    ):
        monkeypatch.delenv(var, raising=False)

    def _mint(sub: str) -> str:
        now = int(time.time())
        return pyjwt.encode(
            {
                "iss": _ISSUER,
                "aud": _AUDIENCE,
                "sub": sub,
                "iat": now,
                "exp": now + 300,
            },
            priv,
            algorithm="ES256",
            headers={"kid": _KID},
        )

    return _mint


# ===========================================================================
# 1. SDK-02 — Authoritative HTTP 200 JWKS Eviction & Failed-Refresh Cooldown
# ===========================================================================


class TestSdk02JwksRevocationAndCooldown:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("label", "bad_200_response"),
        [
            ("empty_keys_revocation", httpx.Response(200, json={"keys": []})),
            ("missing_keys_field", httpx.Response(200, json={"status": "empty"})),
            ("non_object_json", httpx.Response(200, json=[1, 2, 3])),
            ("invalid_json_bytes", httpx.Response(200, content=b"{corrupt-json")),
            ("unsupported_rsa_jwk", httpx.Response(200, json={"keys": [_rsa_jwk()]})),
            (
                "duplicate_kid",
                httpx.Response(
                    200,
                    json={"keys": [_ec_jwk("dup-1")[1], _ec_jwk("dup-1")[1]]},
                ),
            ),
            (
                "exceeds_max_keys",
                httpx.Response(
                    200,
                    json={"keys": [_ec_jwk(f"k-{i}")[1] for i in range(4)]},
                ),
            ),
        ],
    )
    async def test_authoritative_http_200_rejection_evicts_stale_keys_immediately(
        self, label: str, bad_200_response: httpx.Response
    ) -> None:
        """HTTP 200 empty/invalid JWKS during ttl_s <= age < max_staleness_s evicts cached keys immediately."""
        _, jwk_v1 = _ec_jwk("kid-active-1")
        now_box = [1000.0]
        state: dict[str, Any] = {
            "resp": httpx.Response(200, json={"keys": [jwk_v1]}),
            "hits": 0,
        }

        def handler(_req: httpx.Request) -> httpx.Response:
            state["hits"] += 1
            return state["resp"]

        resolver = JwksKeyResolver(
            "https://gateway.example.test/governance/.well-known/jwks.json",
            ttl_s=300.0,
            max_staleness_s=3600.0,
            min_refresh_interval_s=5.0,
            max_keys=3,
            clock=lambda: now_box[0],
        )
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            key = await resolver.resolve_key("kid-active-1", client)
            assert key is not None
            assert state["hits"] == 1

            # Advance into grace window (300s <= 400s < 3600s) and return authoritative 200 rejection
            now_box[0] = 1400.0
            state["resp"] = bad_200_response
            with pytest.raises(
                RoutingSealVerificationError, match="Authoritative JWKS rejection"
            ):
                await resolver.resolve_key("kid-active-1", client)
            assert state["hits"] == 2, label
            assert resolver._keys == {}
            assert resolver._fetched_at is None

            # Within min_refresh_interval_s=5s, retries fail closed without extra HTTP hits
            now_box[0] = 1402.0
            with pytest.raises(
                RoutingSealVerificationError, match="JWKS refresh cooldown active"
            ):
                await resolver.resolve_key("kid-active-1", client)
            assert state["hits"] == 2

            # After cooldown, even a transient 503 cannot resurrect the evicted key
            now_box[0] = 1406.0
            state["resp"] = httpx.Response(503)
            with pytest.raises(
                RoutingSealVerificationError, match="no fresh cached trust anchor"
            ):
                await resolver.resolve_key("kid-active-1", client)
            assert state["hits"] == 3

    @pytest.mark.asyncio
    @pytest.mark.parametrize("failure_mode", ["503", "429", "304", "timeout"])
    async def test_concurrent_20_callers_during_outage_make_single_http_call_per_cooldown(
        self, failure_mode: str
    ) -> None:
        """20 concurrent callers when age >= ttl_s make at most 1 HTTP call per min_refresh_interval_s."""
        _, jwk_v1 = _ec_jwk("kid-grace-1")
        _, jwk_v2 = _ec_jwk("kid-grace-2")
        now_box = [1000.0]
        hits = [0]
        healthy = [True]

        async def async_handler(req: httpx.Request) -> httpx.Response:
            hits[0] += 1
            await asyncio.sleep(0.005)
            if healthy[0]:
                return httpx.Response(200, json={"keys": [jwk_v1, jwk_v2]})
            if failure_mode == "timeout":
                raise httpx.ReadTimeout("JWKS read timed out", request=req)
            return httpx.Response(int(failure_mode))

        resolver = JwksKeyResolver(
            "https://gateway.example.test/governance/.well-known/jwks.json",
            ttl_s=300.0,
            max_staleness_s=3600.0,
            min_refresh_interval_s=10.0,
            clock=lambda: now_box[0],
        )
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(async_handler)
        ) as client:
            # Warm cache at t=1000
            await resolver.resolve_key("kid-grace-1", client)
            assert hits[0] == 1

            # Outage at t=1350 (age=350s >= ttl_s=300s, < max_staleness_s=3600s):
            # 20 concurrent callers for known kid all succeed from grace cache with 1 HTTP hit!
            healthy[0] = False
            now_box[0] = 1350.0
            warm_results = await asyncio.gather(
                *(resolver.resolve_key("kid-grace-1", client) for _ in range(20))
            )
            assert len(warm_results) == 20
            assert hits[0] == 2

            # During active cooldown (t=1354 < 1350 + 10), unknown kid also fails without HTTP hit!
            now_box[0] = 1354.0
            unknown_results = await asyncio.gather(
                *(resolver.resolve_key("unknown-kid", client) for _ in range(20)),
                return_exceptions=True,
            )
            assert hits[0] == 2
            assert all(
                isinstance(r, RoutingSealVerificationError) for r in unknown_results
            )

            # Past max_staleness_s (t=4700 >= 1000 + 3600), 20 concurrent callers fail closed with 1 HTTP hit!
            now_box[0] = 4700.0
            stale_results = await asyncio.gather(
                *(resolver.resolve_key("kid-grace-1", client) for _ in range(20)),
                return_exceptions=True,
            )
            assert hits[0] == 3
            assert all(
                isinstance(r, RoutingSealVerificationError) for r in stale_results
            )

            # Recovery after cooldown clears _last_failed_refresh_at
            healthy[0] = True
            now_box[0] = 4715.0
            recovered = await resolver.resolve_key("kid-grace-2", client)
            assert recovered is not None
            assert resolver._last_failed_refresh_at is None
            assert hits[0] == 4


# ===========================================================================
# 2. DOMADV-05 Part 1 — Post-Rejection & Per-Turn HITL State Cleanup
# ===========================================================================


class TestDomadv05HitlStateCleanup:
    @pytest.mark.asyncio
    async def test_rejected_hitl_turn_clears_deferred_id_so_subsequent_allow_and_skipped_turns_succeed(
        self, gateway
    ) -> None:
        """Rejecting a HITL trade on advisor_session_<user> never traps subsequent ALLOW or SKIPPED turns."""
        mode = ["require_approval"]

        def handler(_req: httpx.Request) -> httpx.Response:
            if mode[0] == "require_approval":
                return httpx.Response(
                    200,
                    json={
                        "verdict": "REQUIRE_APPROVAL",
                        "deferred_id": "def-turn-1",
                        "violations": [],
                    },
                )
            return httpx.Response(
                200, json={"verdict": "ALLOW", "violations": [], "latency_ms": 1.0}
            )

        gateway(handler)
        trader_runs = [0]

        async def fake_trader(state: AgentState) -> dict[str, Any]:
            trader_runs[0] += 1
            return {
                "messages": [("ai", f"Executed clean turn #{trader_runs[0]}")],
                "deferred_id": None,
                "deferred_step_ids": None,
                "approval_decision": None,
                "hitl_reference_quote": None,
            }

        async def fake_explainer(state: AgentState) -> dict[str, Any]:
            last = state["messages"][-1]
            txt = last[1] if isinstance(last, tuple) else getattr(last, "content", "")
            return {"messages": [("ai", f"Summary: {txt}")]}

        def route_after_safety(state: AgentState) -> str:
            status = state.get("safety_status")
            if status in ("APPROVED", "SKIPPED"):
                if state.get("approval_required") or state.get("deferred_id"):
                    return "approval_node"
                return "governed_trader"
            return "explainer"

        workflow = StateGraph(AgentState)
        workflow.add_node("safety_check", safety_check_node)  # type: ignore[arg-type]
        workflow.add_node(
            "approval_node",
            create_approval_node(
                approved_target="governed_trader", rejected_target="explainer"
            ),
        )
        workflow.add_node("governed_trader", fake_trader)  # type: ignore[arg-type]
        workflow.add_node("explainer", fake_explainer)  # type: ignore[arg-type]
        workflow.add_edge(START, "safety_check")
        workflow.add_conditional_edges("safety_check", route_after_safety)
        workflow.add_edge("governed_trader", "explainer")
        workflow.add_edge("explainer", END)
        compiled = workflow.compile(checkpointer=MemorySaver())

        cfg = {"configurable": {"thread_id": "advisor_session_alice"}}
        turn1_plan = {
            "steps": [
                {
                    "action": "execute_trade",
                    "parameters": {
                        "symbol": "NVDA",
                        "amount": 50000,
                        "currency": "USD",
                    },
                }
            ]
        }

        # Turn 1 parks at approval_node
        await compiled.ainvoke(
            {
                "messages": [HumanMessage(content="Buy $50k NVDA")],
                "user_id": "alice",
                "execution_plan_output": turn1_plan,
                "evaluation_result": {"verdict": "APPROVED"},
                "approval_required": True,
                "hitl_reference_quote": {"ticker": "NVDA", "price": 140.0},
            },
            cfg,
        )
        snap_parked = await compiled.aget_state(cfg)
        assert snap_parked.next == ("approval_node",)
        assert snap_parked.values["deferred_id"] == "def-turn-1"

        # Reviewer rejects Turn 1
        res_reject = await compiled.ainvoke(
            Command(
                resume={
                    "approved": False,
                    "reviewer": "compliance@firm.com",
                    "rationale": "Exceeds single-name limit.",
                }
            ),
            cfg,
        )
        assert trader_runs[0] == 0
        assert "Trade Rejected" in str(res_reject["messages"][-1].content)

        snap_after_reject = await compiled.aget_state(cfg)
        assert snap_after_reject.next == ()
        assert snap_after_reject.values.get("deferred_id") is None
        assert snap_after_reject.values.get("deferred_step_ids") is None
        assert snap_after_reject.values.get("approval_decision") is None
        assert snap_after_reject.values.get("hitl_reference_quote") is None
        assert snap_after_reject.values.get("approval_required") is False

        # Turn 2 (ALLOW trade on the SAME thread) executes governed_trader without hitting approval_node!
        mode[0] = "allow"
        turn2_plan = {
            "steps": [
                {
                    "action": "execute_trade",
                    "parameters": {"symbol": "AAPL", "amount": 500, "currency": "USD"},
                }
            ]
        }
        await compiled.ainvoke(
            {
                "messages": [HumanMessage(content="Buy $500 AAPL")],
                "user_id": "alice",
                "execution_plan_output": turn2_plan,
                "evaluation_result": {"verdict": "APPROVED"},
            },
            cfg,
        )
        snap_turn2 = await compiled.aget_state(cfg)
        assert snap_turn2.next == ()
        assert trader_runs[0] == 1

        # Turn 3 (SKIPPED non-trade plan on the SAME thread) also bypasses approval_node!
        await compiled.ainvoke(
            {
                "messages": [HumanMessage(content="What is market status?")],
                "user_id": "alice",
                "execution_plan_output": {"steps": []},
                "evaluation_result": {"verdict": "APPROVED"},
            },
            cfg,
        )
        snap_turn3 = await compiled.aget_state(cfg)
        assert snap_turn3.next == ()
        assert trader_runs[0] == 2

    @pytest.mark.asyncio
    async def test_safety_check_clears_stale_hitl_fields_on_every_exit_path(
        self, gateway
    ) -> None:
        """Every non-HITL safety_check_node exit path explicitly resets stale HITL fields to None."""
        stale_base: dict[str, Any] = {
            "messages": [],
            "user_id": "bob",
            "consecutive_denials": 0,
            "deferred_id": "stale-def-99",
            "deferred_step_ids": ["stale-1", "stale-2"],
            "approval_decision": {"approved": True, "reviewer": "old@firm.com"},
            "hitl_reference_quote": {"ticker": "AAPL", "price": 150.0},
            "execution_plan_output": {
                "action": "execute_trade",
                "symbol": "AAPL",
                "amount": 1000.0,
                "currency": "USD",
                "confidence": 0.99,
            },
        }

        # 1. SKIPPED
        gateway(lambda _r: httpx.Response(500))
        skipped = await safety_check_node(
            {**stale_base, "execution_plan_output": {"action": "research"}}  # type: ignore[arg-type]
        )
        for key in (
            "deferred_id",
            "deferred_step_ids",
            "approval_decision",
            "hitl_reference_quote",
        ):
            assert skipped[key] is None

        # 2. ALLOW (fresh gateway call -> populates routing_verdict_cache for reuse check)
        gateway(
            lambda _r: httpx.Response(
                200, json={"verdict": "ALLOW", "violations": [], "latency_ms": 1.0}
            )
        )
        approved = await safety_check_node(stale_base)  # type: ignore[arg-type]
        assert approved["safety_status"] == "APPROVED"
        for key in (
            "deferred_id",
            "deferred_step_ids",
            "approval_decision",
            "hitl_reference_quote",
        ):
            assert approved[key] is None

        # 3. Reused ALLOW routing_verdict_cache
        gateway(lambda _r: httpx.Response(500))
        reused = await safety_check_node(
            {**stale_base, "routing_verdict_cache": approved["routing_verdict_cache"]}  # type: ignore[arg-type]
        )
        assert reused["safety_status"] == "APPROVED"
        for key in (
            "deferred_id",
            "deferred_step_ids",
            "approval_decision",
            "hitl_reference_quote",
        ):
            assert reused[key] is None

        # 4. DEFERRED
        gateway(
            lambda _r: httpx.Response(
                200,
                json={
                    "verdict": "DEFER",
                    "defer_token": "defer-tok-1",
                    "defer_reason": "CONFIDENCE_BELOW_THRESHOLD",
                    "violations": [],
                },
            )
        )
        deferred = await safety_check_node(stale_base)  # type: ignore[arg-type]
        assert deferred["safety_status"] == "DEFERRED"
        for key in (
            "deferred_id",
            "deferred_step_ids",
            "approval_decision",
            "hitl_reference_quote",
        ):
            assert deferred[key] is None

        # 5. BLOCKED & HARD_PAUSE_BUDGET_EXCEEDED
        gateway(
            lambda _r: httpx.Response(
                403,
                json={
                    "schema_version": "2.0.0",
                    "verdict": "DENIED",
                    "violations": ["limit"],
                    "proof_hash": "sha256:test-stale-reset-1",
                },
            )
        )
        blocked = await safety_check_node(stale_base)  # type: ignore[arg-type]
        hard_pause = await safety_check_node(
            {**stale_base, "consecutive_denials": 1}  # type: ignore[arg-type]
        )
        assert blocked["safety_status"] == "BLOCKED"
        assert hard_pause["safety_status"] == "HARD_PAUSE_BUDGET_EXCEEDED"
        for out in (blocked, hard_pause):
            for key in (
                "deferred_id",
                "deferred_step_ids",
                "approval_decision",
                "hitl_reference_quote",
            ):
                assert out[key] is None

        # 6. GATEWAY_ERROR
        gateway(lambda _r: httpx.Response(503))
        gw_err = await safety_check_node(stale_base)  # type: ignore[arg-type]
        assert gw_err["safety_status"] == "GATEWAY_ERROR"
        for key in (
            "deferred_id",
            "deferred_step_ids",
            "approval_decision",
            "hitl_reference_quote",
        ):
            assert gw_err[key] is None

    def test_rejection_and_drift_blocked_nodes_clear_deferred_step_ids_and_approval_required(
        self,
    ) -> None:
        rej = rejection_node(
            {
                "approval_decision": {
                    "approved": False,
                    "reviewer": "rev@firm.com",
                    "rationale": "Rejected.",
                }
            }
        )
        assert rej["deferred_id"] is None
        assert rej["deferred_step_ids"] is None
        assert rej["approval_decision"] is None
        assert rej["hitl_reference_quote"] is None
        assert rej["approval_required"] is False

        drift = drift_blocked_node(
            {
                "rehydration_result": {
                    "status": "OK",
                    "ticker": "AAPL",
                    "stale_price": 100.0,
                    "fresh_price": 110.0,
                    "drift_pct": 10.0,
                },
                "approval_decision": {
                    "approved": True,
                    "reviewer": "rev@firm.com",
                    "rationale": "Approved.",
                    "max_slippage_pct": 2.0,
                },
                "deferred_id": "d-1",
                "deferred_step_ids": ["d-1", "d-2"],
                "approval_required": True,
            }  # type: ignore[arg-type]
        )
        assert drift["deferred_id"] is None
        assert drift["deferred_step_ids"] is None
        assert drift["approval_decision"] is None
        assert drift["hitl_reference_quote"] is None
        assert drift["approval_required"] is False


# ===========================================================================
# 3. DOMADV-05 Part 2 — Multi-Step REQUIRE_APPROVAL Step-Bound Execution
# ===========================================================================


class TestDomadv05MultiStepHitlExecution:
    @pytest.mark.asyncio
    async def test_multistep_two_require_approval_trades_check_all_tickers_and_bind_per_step_deferred_ids(
        self, gateway
    ) -> None:
        """2-step REQUIRE_APPROVAL plan records deferred_step_ids, checks both tickers' drift, and binds each call."""
        plan = {
            "plan_id": "plan-2-hitl",
            "steps": [
                {
                    "action": "execute_trade",
                    "parameters": {
                        "symbol": "AAPL",
                        "amount": 25000,
                        "currency": "USD",
                    },
                },
                {
                    "action": "execute_trade",
                    "parameters": {
                        "symbol": "NVDA",
                        "amount": 35000,
                        "currency": "USD",
                    },
                },
            ],
        }

        def validate_handler(req: httpx.Request) -> httpx.Response:
            sym = json.loads(req.content)["params"]["symbol"]
            did = "def-aapl-1" if sym == "AAPL" else "def-nvda-2"
            return httpx.Response(
                200,
                json={
                    "verdict": "REQUIRE_APPROVAL",
                    "deferred_id": did,
                    "violations": [],
                },
            )

        gateway(validate_handler)
        initial_state: dict[str, Any] = {
            "messages": [],
            "consecutive_denials": 0,
            "execution_plan_output": plan,
            "hitl_reference_quote": {
                "ticker": "AAPL",
                "price": 200.0,
                "source": "yfinance_check_time",
                "captured_at_utc": "2026-11-21T12:00:00+00:00",
                "quotes_by_ticker": {"AAPL": 200.0, "NVDA": 100.0},
            },
        }
        safety_out = await safety_check_node(initial_state)  # type: ignore[arg-type]
        assert safety_out["deferred_id"] == "def-aapl-1"
        assert safety_out["deferred_step_ids"] == ["def-aapl-1", "def-nvda-2"]

        # Verify approval_node surfaces both deferred_ids to compliance reviewers
        captured_interrupt: dict[str, Any] = {}

        def fake_interrupt(payload: dict[str, Any]) -> dict[str, Any]:
            captured_interrupt.update(payload)
            return {
                "approved": True,
                "reviewer": "pm@firm.com",
                "rationale": "Both rebalance legs approved within 2% slippage.",
                "max_slippage_pct": 2.0,
            }

        with patch(
            "src.governed_financial_advisor.graph.nodes.approval_node.interrupt",
            side_effect=fake_interrupt,
        ):
            cmd = create_approval_node(
                approved_target="governed_trader", rejected_target="explainer"
            )({**initial_state, **safety_out})
        assert captured_interrupt["deferred_ids"] == ["def-aapl-1", "def-nvda-2"]
        assert cmd.goto == "governed_trader"

        # Verify post_hitl_rehydrate_node blocks if NVDA (2nd step) drifted 8% even when AAPL drifted 0.5%!
        trader_state_base: dict[str, Any] = {
            "messages": [],
            "execution_plan": json.dumps(plan),
            "evaluation_result": "APPROVED",
            "deferred_id": safety_out["deferred_id"],
            "deferred_step_ids": safety_out["deferred_step_ids"],
            "approval_required": False,
            "approval_decision": cmd.update["approval_decision"],
            "data_analyst_ticker": safety_out["data_analyst_ticker"],
            "hitl_reference_quote": safety_out["hitl_reference_quote"],
        }

        async def drifted_second_leg(sym: str, **_kw: Any) -> float:
            return 201.0 if sym == "AAPL" else 108.0  # AAPL +0.5%, NVDA +8.0%

        with patch(
            "src.governed_financial_advisor.graph.subgraphs.governed_trader_graph.fetch_live_yfinance_price",
            AsyncMock(side_effect=drifted_second_leg),
        ):
            rehyd_bad = await post_hitl_rehydrate_node(trader_state_base)  # type: ignore[arg-type]
        reval_bad = await post_hitl_revalidate_node(
            {**trader_state_base, **rehyd_bad}  # type: ignore[arg-type]
        )
        assert reval_bad["post_hitl_safety_status"] == "BLOCKED"
        assert rehyd_bad["rehydration_result"]["ticker"] == "NVDA"

        # When both legs stay within 2% slippage, subgraph executes via /tools/execute and binds each call's deferred_id!
        async def within_bounds_quotes(sym: str, **_kw: Any) -> float:
            return 201.0 if sym == "AAPL" else 101.0

        executed_tool_args: list[dict[str, Any]] = []

        def execute_handler(req: httpx.Request) -> httpx.Response:
            body = json.loads(req.content)
            if req.url.path == "/tools/execute":
                params = dict(body["params"])
                executed_tool_args.append(params)
                return httpx.Response(
                    200,
                    json={
                        "status": "SUCCESS",
                        "output": json.dumps(
                            {"status": "FILLED", "symbol": params["symbol"]}
                        ),
                        "outcome": {
                            "status": "EXECUTED",
                            "message": json.dumps(
                                {"status": "FILLED", "symbol": params["symbol"]}
                            ),
                        },
                    },
                )
            return httpx.Response(
                200, json={"verdict": "ALLOW", "violations": [], "latency_ms": 1.0}
            )

        gateway(execute_handler)
        fake_tool = MagicMock()
        fake_tool.name = "execute_trade_action"
        fake_mcp = MagicMock()
        fake_mcp.ensure_connected = AsyncMock()
        fake_mcp.get_tools = AsyncMock(return_value=[fake_tool])

        llm_turns = [0]

        async def fake_llm_invoke(_msgs: list[Any]) -> AIMessage:
            llm_turns[0] += 1
            if llm_turns[0] == 1:
                return AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "id": "call-1",
                            "name": "execute_trade_action",
                            "args": {
                                "symbol": "AAPL",
                                "amount": 25000,
                                "confidence": 0.99,
                                "deferred_id": "forged-by-model",
                            },
                        },
                        {
                            "id": "call-2",
                            "name": "execute_trade_action",
                            "args": {
                                "symbol": "NVDA",
                                "amount": 35000,
                                "confidence": 0.99,
                            },
                        },
                    ],
                )
            return AIMessage(content="Executed both approved legs.")

        fake_llm = MagicMock()
        fake_llm.bind_tools.return_value.ainvoke = AsyncMock(
            side_effect=fake_llm_invoke
        )

        with (
            patch(
                "src.governed_financial_advisor.graph.subgraphs.governed_trader_graph.fetch_live_yfinance_price",
                AsyncMock(side_effect=within_bounds_quotes),
            ),
            patch(
                "src.governed_financial_advisor.graph.subgraphs.governed_trader_graph.get_mcp_client",
                return_value=fake_mcp,
            ),
            patch(
                "src.governed_financial_advisor.graph.subgraphs.governed_trader_graph.chat_model",
                return_value=fake_llm,
            ),
        ):
            subgraph = build_governed_trader_graph()
            parent_out = await governed_trader_node(
                {
                    **initial_state,
                    **safety_out,
                    "evaluation_result": {"verdict": "APPROVED"},
                    "approval_decision": cmd.update["approval_decision"],
                },
                subgraph=subgraph,
            )

        assert len(executed_tool_args) == 2
        assert executed_tool_args[0]["symbol"] == "AAPL"
        assert executed_tool_args[0]["deferred_id"] == "def-aapl-1"
        assert executed_tool_args[1]["symbol"] == "NVDA"
        assert executed_tool_args[1]["deferred_id"] == "def-nvda-2"
        assert parent_out["deferred_id"] is None
        assert parent_out["deferred_step_ids"] is None
        assert parent_out["approval_decision"] is None
        assert parent_out["hitl_reference_quote"] is None

    @pytest.mark.asyncio
    async def test_multistep_tool_guard_revalidates_none_steps_and_fails_closed_on_mismatch(
        self, gateway
    ) -> None:
        """governed_tool_node re-validates None entries in deferred_step_ids and refuses count/tamper mismatches."""
        executed_params: list[dict[str, Any]] = []

        def make_calls(*symbols: str) -> list[dict[str, Any]]:
            return [
                {
                    "id": f"c{idx + 1}",
                    "name": "execute_trade_action",
                    "args": {
                        "symbol": sym,
                        "amount": 1000.0,
                        "confidence": 0.99,
                        "deferred_id": "model-forged",
                    },
                }
                for idx, sym in enumerate(symbols)
            ]

        def _ok_handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            if request.url.path == "/tools/execute":
                executed_params.append(dict(body["params"]))
                return httpx.Response(
                    200,
                    json={
                        "status": "SUCCESS",
                        "output": "ok",
                        "outcome": {"status": "EXECUTED", "message": "ok"},
                    },
                )
            return httpx.Response(
                200, json={"verdict": "ALLOW", "violations": [], "latency_ms": 1.0}
            )

        # 1. Mixed [None, "def-2"] where c1 re-validates ALLOW -> c1 gets no deferred_id, c2 gets "def-2"
        seen = gateway(_ok_handler)
        cmd_ok = await guarded_tool_executor_node(
            {
                "messages": [
                    AIMessage(content="", tool_calls=make_calls("MSFT", "NVDA"))
                ],
                "deferred_id": "def-2",
                "deferred_step_ids": [None, "def-2"],
                "approval_decision": {"approved": True, "reviewer": "r@x.com"},
            }
        )
        ok_res = dict(cmd_ok.update or {})
        preview_reqs = [r for r in seen if r.url.path == "/governance/validate-action"]
        assert len(preview_reqs) == 1  # Only the None step was re-validated
        assert json.loads(preview_reqs[0].content)["params"]["symbol"] == "MSFT"
        assert ok_res["governance_status"] == "ALLOWED"
        assert ok_res["deferred_id"] is None
        assert ok_res["deferred_step_ids"] is None
        assert len(executed_params) == 2
        assert "deferred_id" not in executed_params[0]
        assert executed_params[1]["deferred_id"] == "def-2"

        # 2. Tampered None step now triggers REQUIRE_APPROVAL -> whole batch refused fail-closed!
        gateway(
            lambda _r: httpx.Response(
                200,
                json={
                    "verdict": "REQUIRE_APPROVAL",
                    "deferred_id": "unexpected-def",
                    "violations": [],
                },
            )
        )
        cmd_tamper = await guarded_tool_executor_node(
            {
                "messages": [
                    AIMessage(content="", tool_calls=make_calls("MSFT", "NVDA"))
                ],
                "deferred_id": "def-2",
                "deferred_step_ids": [None, "def-2"],
                "approval_decision": {"approved": True, "reviewer": "r@x.com"},
            }
        )
        tamper_res = dict(cmd_tamper.update or {})
        assert len(executed_params) == 2  # NOT executed again
        assert tamper_res["governance_status"] == "DENIED"
        assert tamper_res["deferred_id"] is None
        assert tamper_res["deferred_step_ids"] is None

        # 3. Call-count mismatch (3 calls vs 2 step_ids) or malformed step_ids -> refused fail-closed!
        for bad_calls, bad_step_ids in (
            (make_calls("AAPL", "MSFT", "NVDA"), ["def-1", "def-2"]),
            (make_calls("AAPL"), ["def-1", "def-2"]),
            (make_calls("AAPL", "NVDA"), [None, None]),
            (make_calls("AAPL", "NVDA"), ["", "def-2"]),
        ):
            cmd_mismatch = await guarded_tool_executor_node(
                {
                    "messages": [AIMessage(content="", tool_calls=bad_calls)],
                    "deferred_id": "def-1",
                    "deferred_step_ids": bad_step_ids,
                    "approval_decision": {"approved": True, "reviewer": "r@x.com"},
                }
            )
            mismatch = dict(cmd_mismatch.update or {})
            assert len(executed_params) == 2
            assert mismatch["governance_status"] == "DENIED"
            assert mismatch["deferred_id"] is None
            assert mismatch["deferred_step_ids"] is None


# ===========================================================================
# 4. DOMADV-05 Part 3 — Authenticated POST /agent/resume & Callback Wiring
# ===========================================================================


class _ResumeState(TypedDict, total=False):
    messages: Annotated[list[Any], add_messages]
    user_id: str
    park: bool
    deferred_id: str | None
    deferred_step_ids: list[str | None] | None
    approval_required: bool
    approval_decision: dict[str, Any] | None
    hitl_expires_at: str | None
    hitl_reference_quote: dict[str, Any] | None
    routing_verdict_cache: dict[str, Any] | None
    execution_plan_output: dict[str, Any] | None
    evaluation_result: dict[str, Any] | None


class TestDomadv05ServerResumeAndCallbacks:
    def _build_parkable_graph(self) -> Any:
        observed_users: list[str | None] = []

        def gate_node(state: dict[str, Any]) -> Command:
            if state.get("park"):
                return create_approval_node(
                    approved_target="finish_ok", rejected_target="finish_rej"
                )(state)
            return Command(goto="finish_ok")

        def finish_ok(_state: dict[str, Any]) -> dict[str, Any]:
            observed_users.append(user_context.get())
            return {"messages": [("ai", "Approved trade completed.")]}

        def finish_rej(state: dict[str, Any]) -> dict[str, Any]:
            observed_users.append(user_context.get())
            rej = rejection_node(state)
            return rej

        builder = StateGraph(_ResumeState)
        builder.add_node("gate", gate_node)
        builder.add_node("finish_ok", finish_ok)
        builder.add_node("finish_rej", finish_rej)
        builder.add_edge(START, "gate")
        builder.add_edge("finish_ok", END)
        builder.add_edge("finish_rej", END)
        compiled = builder.compile(checkpointer=MemorySaver())
        compiled._observed_users = observed_users  # type: ignore[attr-defined]
        return compiled

    @pytest.mark.asyncio
    async def test_agent_resume_auth_ownership_interrupt_errors_and_happy_paths(
        self,
        advisor_server: Any,
        mint_user_jwt: Callable[[str], str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        graph = self._build_parkable_graph()
        cb_threads: list[str] = []

        def fake_cb_factory(tid: str) -> Any:
            cb_threads.append(tid)
            return None

        # Verify custom callback handler wiring using a real BaseCallbackHandler
        from langchain_core.callbacks import BaseCallbackHandler

        class _SpyCallback(BaseCallbackHandler):
            pass

        def spy_cb_factory(tid: str) -> BaseCallbackHandler:
            cb_threads.append(tid)
            return _SpyCallback()

        graph._provider_02_callback_factory = spy_cb_factory
        monkeypatch.setattr(advisor_server.app.state, "graph", graph, raising=False)

        # Seed parked thread for bob, completed thread for bob, ownerless parked thread,
        # and reserved-prefix mismatch thread
        await graph.ainvoke(
            {
                "messages": [("user", "Buy AAPL")],
                "user_id": "bob",
                "park": True,
                "deferred_id": "def-bob-1",
                "execution_plan_output": {"symbol": "AAPL", "amount": 25000},
                "evaluation_result": {"verdict": "REQUIRE_APPROVAL"},
            },
            {"configurable": {"thread_id": "advisor_session_bob"}},
        )
        await graph.ainvoke(
            {
                "messages": [("user", "Buy MSFT")],
                "user_id": "bob",
                "park": True,
                "deferred_id": "def-bob-2",
                "execution_plan_output": {"symbol": "MSFT", "amount": 30000},
                "evaluation_result": {"verdict": "REQUIRE_APPROVAL"},
            },
            {"configurable": {"thread_id": "bob-reject-thread"}},
        )
        await graph.ainvoke(
            {"messages": [("user", "Hello")], "user_id": "bob", "park": False},
            {"configurable": {"thread_id": "bob-done-thread"}},
        )
        await graph.ainvoke(
            {
                "messages": [("user", "No owner")],
                "user_id": "   ",
                "park": True,
                "deferred_id": "def-ownerless-1",
            },
            {"configurable": {"thread_id": "ownerless-thread"}},
        )
        await graph.ainvoke(
            {
                "messages": [("user", "Mismatch")],
                "user_id": "bob",
                "park": True,
                "deferred_id": "def-alice-1",
            },
            {"configurable": {"thread_id": "advisor_session_alice"}},
        )

        alice_jwt = mint_user_jwt("alice")
        svc_headers = {"Authorization": f"Bearer {_SERVICE_KEY}"}
        valid_body = {
            "thread_id": "advisor_session_bob",
            "approved": True,
            "reviewer": "approver@firm.com",
            "rationale": "Mandate verified against IPS.",
            "max_slippage_pct": 1.5,
        }

        client = TestClient(advisor_server.app)

        # 1. End-user OIDC JWT rejected with 401; missing auth rejected with 401
        assert (
            client.post(
                "/agent/resume",
                json=valid_body,
                headers={"Authorization": f"Bearer {alice_jwt}"},
            ).status_code
            == 401
        )
        assert client.post("/agent/resume", json=valid_body).status_code == 401

        # 2. Validation errors: empty rationale or invalid slippage -> 422
        assert (
            client.post(
                "/agent/resume",
                json={**valid_body, "rationale": "   "},
                headers=svc_headers,
            ).status_code
            == 422
        )
        assert (
            client.post(
                "/agent/resume",
                json={**valid_body, "max_slippage_pct": 150.0},
                headers=svc_headers,
            ).status_code
            == 422
        )

        # 3. Unknown thread -> 404
        assert (
            client.post(
                "/agent/resume",
                json={**valid_body, "thread_id": "nonexistent-thread"},
                headers=svc_headers,
            ).status_code
            == 404
        )

        # 4. Ownerless checkpoint -> 403
        assert (
            client.post(
                "/agent/resume",
                json={**valid_body, "thread_id": "ownerless-thread"},
                headers=svc_headers,
            ).status_code
            == 403
        )

        # 5. Mismatched user_id or mismatched X-CAGE-User-Token or reserved prefix -> 403
        assert (
            client.post(
                "/agent/resume",
                json={**valid_body, "user_id": "alice"},
                headers=svc_headers,
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/agent/resume",
                json=valid_body,
                headers={**svc_headers, "X-CAGE-User-Token": alice_jwt},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/agent/resume",
                json={**valid_body, "thread_id": "advisor_session_alice"},
                headers=svc_headers,
            ).status_code
            == 403
        )

        # 6. Non-interrupted thread -> 409
        assert (
            client.post(
                "/agent/resume",
                json={**valid_body, "thread_id": "bob-done-thread"},
                headers=svc_headers,
            ).status_code
            == 409
        )

        # 7. Approved resume succeeds, binds user_context("bob"), and wires _provider_02_callback_factory
        ok_resp = client.post("/agent/resume", json=valid_body, headers=svc_headers)
        assert ok_resp.status_code == 200
        assert ok_resp.json()["response"] == "Approved trade completed."
        assert graph._observed_users[-1] == "bob"
        assert user_context.get() == "default_user"
        assert "advisor_session_bob" in cb_threads

        # Re-resuming the now-completed thread returns 409
        assert (
            client.post(
                "/agent/resume", json=valid_body, headers=svc_headers
            ).status_code
            == 409
        )

        # 8. Rejected resume succeeds and surfaces rejection text
        rej_resp = client.post(
            "/agent/resume",
            json={
                "thread_id": "bob-reject-thread",
                "user_id": "bob",
                "approved": False,
                "reviewer": "approver@firm.com",
                "rationale": "Concentration risk too high.",
            },
            headers=svc_headers,
        )
        assert rej_resp.status_code == 200
        assert "Trade Rejected" in rej_resp.json()["response"]
        assert "bob-reject-thread" in cb_threads

    @pytest.mark.covers(
        "src.governed_financial_advisor.server:resume_agent#Checkpoint store unavailable while preparing thread resume"
    )
    def test_agent_query_wires_provider_02_callback_factory_and_resume_maps_503_504(
        self,
        advisor_server: Any,
        mint_user_jwt: Callable[[str], str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        alice_jwt = mint_user_jwt("alice")
        svc_headers = {"Authorization": f"Bearer {_SERVICE_KEY}"}
        captured_configs: list[dict[str, Any]] = []

        mock_graph = MagicMock()
        mock_graph._provider_02_callback_factory = lambda tid: f"cb:{tid}"
        mock_graph.checkpointer = None

        async def fake_ainvoke(_inp: Any, cfg: dict[str, Any]) -> dict[str, Any]:
            captured_configs.append(cfg)
            return {
                "messages": [("ai", "Query response ok.")],
                "safety_status": "SKIPPED",
            }

        mock_graph.ainvoke = AsyncMock(side_effect=fake_ainvoke)
        monkeypatch.setattr(
            advisor_server.app.state, "graph", mock_graph, raising=False
        )

        mock_cache = MagicMock()
        mock_cache.get = AsyncMock(return_value=None)
        mock_cache.set = AsyncMock(return_value=None)

        client = TestClient(advisor_server.app)
        with patch(
            "src.governed_financial_advisor.infrastructure.query_cache.get_query_cache",
            AsyncMock(return_value=mock_cache),
        ):
            q_resp = client.post(
                "/agent/query",
                json={
                    "prompt": "Check portfolio",
                    "user_id": "alice",
                    "thread_id": "t-cb-1",
                },
                headers={"Authorization": f"Bearer {alice_jwt}"},
            )
        assert q_resp.status_code == 200
        assert captured_configs[-1]["callbacks"] == ["cb:t-cb-1"]

        # CheckpointDurabilityError -> 503 on /agent/resume
        mock_graph.aget_state = AsyncMock(
            side_effect=CheckpointDurabilityError("redis down")
        )
        r_503 = client.post(
            "/agent/resume",
            json={
                "thread_id": "t-cb-1",
                "approved": True,
                "reviewer": "op@firm.com",
                "rationale": "Approved.",
            },
            headers=svc_headers,
        )
        assert r_503.status_code == 503

        # TimeoutError -> 504 on /agent/resume
        mock_graph.aget_state = AsyncMock(
            return_value=SimpleNamespace(
                values={"user_id": "alice"},
                next=("approval_node",),
                tasks=[
                    SimpleNamespace(interrupts=[SimpleNamespace(value={"reason": "x"})])
                ],
            )
        )
        mock_graph.ainvoke = AsyncMock(side_effect=asyncio.TimeoutError())
        r_504 = client.post(
            "/agent/resume",
            json={
                "thread_id": "t-cb-1",
                "approved": True,
                "reviewer": "op@firm.com",
                "rationale": "Approved.",
            },
            headers=svc_headers,
        )
        assert r_504.status_code == 504
