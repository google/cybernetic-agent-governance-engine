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

"""Unit tests for ``safety_check_node`` (R-20, POAM-2026-080).

The safety node submits the proposed trade to the gateway's
``POST /governance/validate-action`` through the advisor's standard
``GatewayClient``. These tests drive the real ``GatewayClient`` over an
``httpx.MockTransport`` so the node's handling of each gateway response is
observed end to end — including every fail-closed path (denial, HTTP error,
timeout, unreachable gateway, non-APPROVED verdicts).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest

from src.governed_financial_advisor.graph.nodes.safety_node import (
    MAX_CONSECUTIVE_DENIALS,
    route_safety,
    safety_check_node,
)
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient

pytestmark = [pytest.mark.unit, pytest.mark.local]

Handler = Callable[[httpx.Request], httpx.Response]


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


def _trade_state(**overrides: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "messages": [],
        "user_id": "trader_001",
        "risk_attitude": "moderate",
        "consecutive_denials": 0,
        "execution_plan_output": {
            "action": "execute_trade",
            "amount": 3000,
            "symbol": "AAPL",
            "currency": "USD",
            "trader_role": "junior",
            "confidence": 0.99,
        },
    }
    state.update(overrides)
    return state


def _approved_envelope() -> dict[str, Any]:
    return {
        "envelope_version": "3.0",
        "envelope_id": "env-1",
        "signature": "sig-abc",
        "payload": {"verdict": "ALLOW", "violations": [], "latency_ms": 4.2},
    }


class TestSafetyNodeGatewayCall:
    @pytest.mark.asyncio
    async def test_submits_trade_to_validate_action(self, gateway) -> None:
        seen = gateway(lambda r: httpx.Response(200, json=_approved_envelope()))

        await safety_check_node(_trade_state())

        assert len(seen) == 1
        assert seen[0].url.path == "/governance/validate-action"
        body = json.loads(seen[0].content)
        assert body["action"] == "execute_trade"
        assert body["params"]["symbol"] == "AAPL"
        assert body["params"]["amount"] == 3000.0
        # Zero-identity client: no routing-seal header is ever sent.
        assert "x-cage-routing-seal" not in seen[0].headers

    @pytest.mark.asyncio
    async def test_non_trade_plan_skips_gateway(self, gateway) -> None:
        seen = gateway(lambda r: httpx.Response(500))

        result = await safety_check_node(
            _trade_state(execution_plan_output={"action": "research"})
        )

        assert result == {"safety_status": "SKIPPED"}
        assert seen == []


class TestSafetyNodeVerdicts:
    @pytest.mark.asyncio
    async def test_approved_verdict_approves_and_resets_denials(self, gateway) -> None:
        gateway(lambda r: httpx.Response(200, json=_approved_envelope()))

        result = await safety_check_node(_trade_state(consecutive_denials=1))

        assert result["safety_status"] == "APPROVED"
        assert result["consecutive_denials"] == 0
        assert result["last_violation"] is None
        assert result["governance_signature"] == "sig-abc"

    @pytest.mark.parametrize(
        "body",
        [
            {"verdict": "NARROW", "violations": [], "narrowed_params": {"amount": 1.0}},
            {"verdict": "REQUIRE_APPROVAL", "deferred_id": "d-1", "violations": []},
        ],
        ids=["narrow", "require-approval"],
    )
    @pytest.mark.asyncio
    async def test_routable_verdicts_proceed_to_the_trader(self, gateway, body) -> None:
        """The trader's tool guard re-asks the gateway and parks approvals."""
        gateway(lambda r: httpx.Response(200, json=body))

        result = await safety_check_node(_trade_state(consecutive_denials=1))

        assert result["safety_status"] == "APPROVED"
        assert result["consecutive_denials"] == 0

    @pytest.mark.asyncio
    async def test_defer_with_ticket_defers(self, gateway) -> None:
        gateway(
            lambda r: httpx.Response(
                202,
                json={
                    "verdict": "DEFER",
                    "defer_id": "ticket-9",
                    "defer_reason": "EXTERNAL_HOLD",
                },
            )
        )

        result = await safety_check_node(_trade_state())

        assert result["safety_status"] == "DEFERRED"
        assert result["deferral_ticket_id"] == "ticket-9"
        assert result["deferral_reason"] == "EXTERNAL_HOLD"


class TestSafetyNodeFailClosed:
    """Every non-APPROVED outcome must block — never approve."""

    @pytest.mark.asyncio
    async def test_gateway_denial_403_blocks(self, gateway) -> None:
        gateway(
            lambda r: httpx.Response(
                403,
                json={"verdict": "DENIED", "violations": ["junior trade above limit"]},
            )
        )

        result = await safety_check_node(_trade_state())

        assert result["safety_status"] == "BLOCKED"
        assert result["consecutive_denials"] == 1
        assert result["last_violation"]["reason_code"] == "GOVERNANCE_DENIED"
        assert "junior trade above limit" in result["last_violation"]["evidence"]

    @pytest.mark.asyncio
    async def test_denied_verdict_in_200_body_blocks(self, gateway) -> None:
        gateway(
            lambda r: httpx.Response(
                200, json={"verdict": "DENIED", "violations": ["cbf barrier"]}
            )
        )

        result = await safety_check_node(_trade_state())

        assert result["safety_status"] == "BLOCKED"
        assert result["last_violation"]["reason_code"] == "GOVERNANCE_DENIED"

    @pytest.mark.asyncio
    async def test_gateway_500_blocks(self, gateway) -> None:
        gateway(lambda r: httpx.Response(500, json={"detail": "boom"}))

        result = await safety_check_node(_trade_state())

        assert result["safety_status"] == "BLOCKED"
        assert result["last_violation"]["policy_rule"] == "GATEWAY_ERROR"
        assert result["last_violation"]["recoverable"] is False

    @pytest.mark.asyncio
    async def test_gateway_unauthenticated_401_blocks(self, gateway) -> None:
        gateway(lambda r: httpx.Response(401, json={"detail": "no workload identity"}))

        result = await safety_check_node(_trade_state())

        assert result["safety_status"] == "BLOCKED"
        assert result["last_violation"]["policy_rule"] == "GATEWAY_ERROR"

    @pytest.mark.asyncio
    async def test_gateway_timeout_blocks(self, gateway) -> None:
        def timeout(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("gateway too slow", request=request)

        gateway(timeout)

        result = await safety_check_node(_trade_state())

        assert result["safety_status"] == "BLOCKED"
        assert result["last_violation"]["policy_rule"] == "GATEWAY_ERROR"
        assert "ReadTimeout" in result["last_violation"]["evidence"]

    @pytest.mark.asyncio
    async def test_gateway_unreachable_blocks(self, gateway) -> None:
        def refused(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        gateway(refused)

        result = await safety_check_node(_trade_state())

        assert result["safety_status"] == "BLOCKED"
        assert "ConnectError" in result["last_violation"]["evidence"]

    @pytest.mark.parametrize(
        "body",
        [
            {"verdict": "PAUSE"},
            {"verdict": "DEFER"},  # DEFER without a ticket cannot be parked
            {"verdict": "approved"},
            {"verdict": "APPROVED"},  # legacy vocabulary is not routable
            {"verdict": "REQUIRE_APPROVAL"},  # no deferred_id was parked
            {"violations": []},
        ],
    )
    @pytest.mark.asyncio
    async def test_non_approved_verdicts_block(self, gateway, body) -> None:
        gateway(lambda r: httpx.Response(200, json=body))

        result = await safety_check_node(_trade_state())

        assert result["safety_status"] == "BLOCKED"
        # GatewayClient defaults a missing verdict to DENIED; both labels block.
        assert result["last_violation"]["reason_code"] in {
            "NOT_APPROVED",
            "GOVERNANCE_DENIED",
        }

    @pytest.mark.asyncio
    async def test_denial_budget_exhaustion_hard_pauses(self, gateway) -> None:
        gateway(lambda r: httpx.Response(403, json={"verdict": "DENIED"}))

        result = await safety_check_node(
            _trade_state(consecutive_denials=MAX_CONSECUTIVE_DENIALS - 1)
        )

        assert result["safety_status"] == "HARD_PAUSE_BUDGET_EXCEEDED"
        assert result["consecutive_denials"] == MAX_CONSECUTIVE_DENIALS


class TestRouteSafety:
    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            ("APPROVED", "governed_trader"),
            ("DEFERRED", "defer_node"),
            ("HARD_PAUSE_BUDGET_EXCEEDED", "human_review"),
            ("BLOCKED", "explainer"),
            ("SKIPPED", "explainer"),
            ("UNKNOWN", "explainer"),
        ],
    )
    def test_route_safety(self, status: str, expected: str) -> None:
        assert route_safety({"safety_status": status}) == expected
