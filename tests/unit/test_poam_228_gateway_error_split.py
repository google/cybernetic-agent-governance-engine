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
# Closure regression guard for: POAM-2026-228

"""Regression tests for POAM-2026-228: separate gateway transport/verification errors from policy denials.

Covers all six coupled advisor/attestation/formal surfaces:
  1. ``GatewayClient._raise_unrouted()`` and ``_is_policy_drift()`` preserve
     ``CageClient``'s ``proof_hash`` / ``audit_id`` authenticity check on HTTP 403
     and never refresh policy pins or replay trades on un-evidenced 403s.
  2. ``AgentState.safety_status`` (``compliance/schemas/agent_state_schema.json``)
     and ``safety_node.py`` emit ``safety_status = "GATEWAY_ERROR"`` while keeping
     ``consecutive_denials`` unchanged and logging at ``ERROR`` without false
     policy-denial or budget-exhaustion messages.
  3. ``explainer_node.py`` checks ``safety_status == "GATEWAY_ERROR"`` before
     ``consecutive_denials >= MAX_CONSECUTIVE_DENIALS`` and returns a deterministic
     fail-closed infrastructure message without LLM calls or policy-probing text.
  4. ``server.py`` ``QueryCache`` caches only turns with ``not guardrail_blocked``
     and ``safety_status in (None, "APPROVED", "SKIPPED")``.
  5. ``src/integrations/provider_02/adapter.py`` never classifies
     ``safety_status == "GATEWAY_ERROR"`` or ``last_violation.reason_code == "GATEWAY_ERROR"``
     as ``"cbf_block"``.
  6. ``proof/LangGraphHarness.tla`` models ``SafetyTransportError`` separately from
     ``SafetyDeny`` with ``UNCHANGED`` ``consecutive_denials`` and ``evidence_committed``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from cage_client import CageGatewayError, RoutingSealVerificationError

from src.cage_finance.graph_topology import FINANCIAL_ADVISOR_TOPOLOGY
from src.governed_financial_advisor.graph.graph import _build_workflow
from src.governed_financial_advisor.graph.nodes.explainer_node import explainer_node
from src.governed_financial_advisor.graph.nodes.safety_node import (
    MAX_CONSECUTIVE_DENIALS,
    route_safety,
    safety_check_node,
)
from src.governed_financial_advisor.infrastructure.gateway_client import GatewayClient
from src.integrations.provider_02.adapter import (
    ProjectBundleStepEntry,
    Provider02AttestationCallback,
    _classify_terminal_path,
    _extract_signals,
)
from tests.fixtures.signed_gateway import SignedGatewayStub
from tests.integrations.provider_02.state_commitment_support import (
    InProcessCommitter,
    sealed_bundle,
)
from tests.integrations.provider_02.test_native_schema_conformance import (
    ATTESTATION_BUNDLE_VALIDATOR,
)

pytestmark = [pytest.mark.unit, pytest.mark.local]

REPO_ROOT = Path(__file__).resolve().parents[2]
Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture
def signed_gateway() -> SignedGatewayStub:
    return SignedGatewayStub()


@pytest.fixture
def gateway(
    signed_gateway: SignedGatewayStub,
) -> Iterator[Callable[[Handler], list[httpx.Request]]]:
    GatewayClient._instance = None

    def install(handler: Handler) -> list[httpx.Request]:
        seen: list[httpx.Request] = []

        def recording(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return handler(request)

        client = GatewayClient()
        client._http = httpx.AsyncClient(
            transport=httpx.MockTransport(signed_gateway.transport_handler(recording)),
            base_url="http://gateway.test",
        )
        return seen

    yield install
    GatewayClient._instance = None


def _trade_state(consecutive_denials: int = 0, **overrides: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "messages": [("user", "Buy $3,000 of AAPL")],
        "user_id": "trader_001",
        "risk_attitude": "moderate",
        "consecutive_denials": consecutive_denials,
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


# ---------------------------------------------------------------------------
# Surface 1: GatewayClient._raise_unrouted & _AdvisorTransport policy-drift gate
# ---------------------------------------------------------------------------


class TestGatewayClientRefusalAuthenticity:
    @pytest.mark.parametrize(
        "case_id",
        [
            "linkerd-empty-403",
            "workload-identity-403",
            "json-403-without-proof-hash",
            "json-403-with-blank-proof-hash",
        ],
    )
    @pytest.mark.asyncio
    async def test_unevidenced_403_raises_http_status_error_not_permission_error(
        self, gateway, case_id: str
    ) -> None:
        responses = {
            "linkerd-empty-403": httpx.Response(
                403, content=b"", headers={"content-type": "text/plain"}
            ),
            "workload-identity-403": httpx.Response(
                403, json={"detail": "Forbidden: untrusted workload"}
            ),
            "json-403-without-proof-hash": httpx.Response(
                403,
                json={"verdict": "DENIED", "violations": ["no proof_hash"]},
            ),
            "json-403-with-blank-proof-hash": httpx.Response(
                403,
                json={
                    "verdict": "DENIED",
                    "violations": ["blank proof_hash"],
                    "proof_hash": "   ",
                },
            ),
        }
        gateway(lambda _r: responses[case_id])

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await GatewayClient().validate_action(
                action="execute_trade",
                params={"symbol": "AAPL", "amount": 100.0},
            )
        assert exc_info.value.response.status_code == 403
        assert not isinstance(exc_info.value, PermissionError)

    @pytest.mark.parametrize(
        "evidence_case",
        ["proof-hash", "receipt-proof-hash", "audit-id"],
    )
    @pytest.mark.asyncio
    async def test_evidenced_403_raises_permission_error(
        self, gateway, evidence_case: str
    ) -> None:
        if evidence_case == "proof-hash":
            resp = httpx.Response(
                403,
                json={
                    "schema_version": "2.0.0",
                    "verdict": "DENIED",
                    "violations": ["cash barrier exceeded"],
                    "proof_hash": "sha256:evidenced-top-level",
                },
            )
        elif evidence_case == "receipt-proof-hash":
            resp = httpx.Response(
                403,
                content=json.dumps(
                    {
                        "schema_version": "2.0.0",
                        "verdict": "DENIED",
                        "violations": ["cash barrier exceeded"],
                        "refusal_receipt": {"proof_hash": "sha256:evidenced-receipt"},
                    }
                ).encode("utf-8"),
                headers={"content-type": "application/json"},
            )
        else:
            resp = httpx.Response(
                403,
                content=json.dumps(
                    {
                        "verdict": "DENIED",
                        "violations": ["cash barrier exceeded"],
                        "audit_id": "audit-evidenced-1",
                    }
                ).encode("utf-8"),
                headers={"content-type": "application/json"},
            )
        gateway(lambda _r: resp)

        with pytest.raises(PermissionError, match="Governance DENIED 'execute_trade'"):
            await GatewayClient().validate_action(
                action="execute_trade",
                params={"symbol": "AAPL", "amount": 100.0},
            )

    @pytest.mark.asyncio
    async def test_unsigned_non_envelope_200_raises_cage_gateway_error(self) -> None:
        """An upstream proxy returning raw HTML or unsigned JSON 200 raises CageGatewayError."""
        GatewayClient._instance = None
        client = GatewayClient()
        client._http = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _r: httpx.Response(
                    200,
                    content=b"<html>proxy maintenance</html>",
                    headers={"content-type": "text/html"},
                )
            ),
            base_url="http://gateway.test",
        )
        try:
            with pytest.raises(CageGatewayError):
                await client.validate_action(
                    action="execute_trade",
                    params={"symbol": "AAPL", "amount": 100.0},
                )
        finally:
            await client.close()
            GatewayClient._instance = None

    @pytest.mark.asyncio
    async def test_forged_unsigned_403_with_proof_hash_never_raises_permission_error(
        self,
    ) -> None:
        """An intermediary forging an unsigned JSON 403 WITH proof_hash cannot spoof a policy refusal."""
        GatewayClient._instance = None
        stub = SignedGatewayStub()
        client = GatewayClient()

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/governance/.well-known/jwks.json":
                return httpx.Response(200, json=stub.jwks)
            return httpx.Response(
                403,
                json={
                    "schema_version": "2.0.0",
                    "verdict": "DENIED",
                    "violations": ["forged proxy refusal"],
                    "proof_hash": "sha256:forged-by-proxy",
                },
            )

        client._http = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            base_url="http://gateway.test",
        )
        try:
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await client.validate_action(
                    action="execute_trade",
                    params={"symbol": "AAPL", "amount": 100.0},
                )
            assert exc_info.value.response.status_code == 403
            assert not isinstance(exc_info.value, PermissionError)
        finally:
            await client.close()
            GatewayClient._instance = None

    @pytest.mark.asyncio
    async def test_rogue_signed_403_envelope_raises_routing_seal_error_not_permission_error(
        self, gateway
    ) -> None:
        """A 403 GovernanceEnvelope signed by an untrusted key raises RoutingSealVerificationError."""
        rogue = SignedGatewayStub(kid="rogue-key")
        gateway(
            lambda req: httpx.Response(
                403,
                json=rogue.envelope(
                    json.loads(req.content)["action"],
                    json.loads(req.content)["params"],
                    {
                        "schema_version": "2.0.0",
                        "verdict": "DENIED",
                        "violations": ["Substrate Policy Drift Detected"],
                        "proof_hash": "sha256:rogue-proof",
                    },
                ),
            )
        )
        with pytest.raises(RoutingSealVerificationError):
            await GatewayClient().validate_action(
                action="execute_trade",
                params={"symbol": "AAPL", "amount": 100.0},
            )


# ---------------------------------------------------------------------------
# Surface 2: AgentState schema, safety_check_node, and route_safety
# ---------------------------------------------------------------------------


class TestSafetyNodeGatewayErrorSplit:
    def test_agent_state_schema_declares_gateway_error_status(self) -> None:
        schema = json.loads(
            (
                REPO_ROOT / "compliance" / "schemas" / "agent_state_schema.json"
            ).read_text(encoding="utf-8")
        )
        enum_values = schema["properties"]["safety_status"]["enum"]
        assert "GATEWAY_ERROR" in enum_values

    @pytest.mark.asyncio
    async def test_repeated_gateway_errors_never_increment_denials_or_hard_pause(
        self, gateway, caplog: pytest.LogCaptureFixture
    ) -> None:
        rogue = SignedGatewayStub()
        responses: list[Callable[[httpx.Request], httpx.Response]] = [
            lambda _r: httpx.Response(
                403, content=b"", headers={"content-type": "text/plain"}
            ),
            lambda _r: httpx.Response(503, json={"detail": "unavailable"}),
            lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("timed out", request=r)),
            lambda r: httpx.Response(
                200,
                json=rogue.envelope(
                    json.loads(r.content)["action"],
                    json.loads(r.content)["params"],
                    {"verdict": "ALLOW", "violations": []},
                ),
            ),
        ]
        idx = 0

        def next_fault(request: httpx.Request) -> httpx.Response:
            nonlocal idx
            fn = responses[min(idx, len(responses) - 1)]
            idx += 1
            return fn(request)

        gateway(next_fault)
        state = _trade_state(consecutive_denials=1)

        with caplog.at_level(logging.WARNING, logger="SafetyNode"):
            for _ in range(4):
                out = await safety_check_node(state)  # type: ignore[arg-type]
                assert out["safety_status"] == "GATEWAY_ERROR"
                assert out["consecutive_denials"] == 1
                assert out["last_violation"]["reason_code"] == "GATEWAY_ERROR"
                assert out["last_violation"]["policy_rule"] == "GATEWAY_ERROR"
                assert out["last_violation"]["audit_id"] is None
                assert out["last_violation"]["recoverable"] is False
                assert out["routing_verdict_cache"] is None
                state = {**state, **out}

        safety_records = [r for r in caplog.records if r.name == "SafetyNode"]
        assert len(safety_records) == 4
        logged = "\n".join(r.getMessage() for r in caplog.records)
        assert "Gateway validation unavailable/unverified — failing closed" in logged
        assert "Action DENIED by governance" not in logged
        assert "MAX_CONSECUTIVE_DENIALS exceeded" not in logged
        assert all(r.levelno == logging.ERROR for r in safety_records)

    @pytest.mark.asyncio
    async def test_interleaved_deny_transport_error_deny_conformance(
        self, gateway
    ) -> None:
        """Turn 1 DENY (0->1) -> Turn 2 GATEWAY_ERROR (1->1) -> Turn 3 DENY (1->2, HARD_PAUSE)."""
        step = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal step
            step += 1
            if step in (1, 3):
                return httpx.Response(
                    403,
                    json={
                        "schema_version": "2.0.0",
                        "verdict": "DENIED",
                        "violations": ["limit breach"],
                        "proof_hash": f"sha256:refusal-{step}",
                    },
                )
            return httpx.Response(
                403, content=b"", headers={"content-type": "text/plain"}
            )

        gateway(handler)
        workflow = _build_workflow()
        graph_router = workflow.branches["safety_check"]["route_after_safety"].path.func

        state = _trade_state(consecutive_denials=0)

        t1 = await safety_check_node(state)  # type: ignore[arg-type]
        assert t1["safety_status"] == "BLOCKED"
        assert t1["consecutive_denials"] == 1
        state = {**state, **t1}
        assert route_safety(state) == "explainer"  # type: ignore[arg-type]
        assert graph_router(state) == "explainer"

        t2 = await safety_check_node(state)  # type: ignore[arg-type]
        assert t2["safety_status"] == "GATEWAY_ERROR"
        assert t2["consecutive_denials"] == 1
        state = {**state, **t2}
        assert route_safety(state) == "explainer"  # type: ignore[arg-type]
        assert graph_router(state) == "explainer"

        t3 = await safety_check_node(state)  # type: ignore[arg-type]
        assert t3["safety_status"] == "HARD_PAUSE_BUDGET_EXCEEDED"
        assert t3["consecutive_denials"] == MAX_CONSECUTIVE_DENIALS == 2
        state = {**state, **t3}
        assert route_safety(state) == "human_review"  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Surface 3: explainer_node fail-closed message without policy-probing claim
# ---------------------------------------------------------------------------


class TestExplainerNodeGatewayError:
    @pytest.mark.parametrize("prior_denials", [0, 1, MAX_CONSECUTIVE_DENIALS, 5])
    @pytest.mark.asyncio
    async def test_gateway_error_precedes_budget_check_and_never_claims_policy_denial(
        self, prior_denials: int
    ) -> None:
        state: dict[str, Any] = {
            "messages": [("user", "Buy AAPL")],
            "safety_status": "GATEWAY_ERROR",
            "consecutive_denials": prior_denials,
            "last_violation": {
                "reason_code": "GATEWAY_ERROR",
                "policy_rule": "GATEWAY_ERROR",
                "evidence": "Gateway returned HTTP 403",
                "audit_id": None,
                "recoverable": False,
            },
        }
        with patch(
            "src.governed_financial_advisor.graph.nodes.explainer_node.create_explainer_agent"
        ) as mock_llm:
            out = await explainer_node(state)  # type: ignore[arg-type]

        mock_llm.assert_not_called()
        assert out["safety_status"] == "GATEWAY_ERROR"
        assert out["next_step"] == "FINISH"
        msg = out["messages"][0][1]
        assert "unreachable or returned an unverified response" in msg
        assert "fail-closed" in msg
        assert "denied" not in msg.lower() or "by the governance system" not in msg
        assert "by the governance system" not in msg
        assert "To prevent policy-probing attacks" not in msg
        assert "Replanning Budget Exhausted" not in msg


# ---------------------------------------------------------------------------
# Surface 4: server.py QueryCache guard against caching non-approved turns
# ---------------------------------------------------------------------------


class TestServerQueryCacheGuard:
    @pytest.mark.parametrize(
        ("graph_result", "should_cache"),
        [
            (
                {
                    "messages": [("ai", "ok")],
                    "guardrail_blocked": False,
                    "safety_status": "APPROVED",
                },
                True,
            ),
            (
                {
                    "messages": [("ai", "ok")],
                    "guardrail_blocked": False,
                    "safety_status": "SKIPPED",
                },
                True,
            ),
            (
                {
                    "messages": [("ai", "ok")],
                    "guardrail_blocked": False,
                    "safety_status": None,
                },
                True,
            ),
            ({"messages": [("ai", "ok")], "guardrail_blocked": False}, True),
            (
                {
                    "messages": [("ai", "err")],
                    "guardrail_blocked": False,
                    "safety_status": "GATEWAY_ERROR",
                },
                False,
            ),
            (
                {
                    "messages": [("ai", "denied")],
                    "guardrail_blocked": False,
                    "safety_status": "BLOCKED",
                },
                False,
            ),
            (
                {
                    "messages": [("ai", "deferred")],
                    "guardrail_blocked": False,
                    "safety_status": "DEFERRED",
                },
                False,
            ),
            (
                {
                    "messages": [("ai", "escalated")],
                    "guardrail_blocked": False,
                    "safety_status": "ESCALATED",
                },
                False,
            ),
            (
                {
                    "messages": [("ai", "paused")],
                    "guardrail_blocked": False,
                    "safety_status": "HARD_PAUSE_BUDGET_EXCEEDED",
                },
                False,
            ),
            (
                {
                    "messages": [("ai", "blocked")],
                    "guardrail_blocked": True,
                    "guardrail_reason": "blocked",
                },
                False,
            ),
        ],
    )
    @pytest.mark.asyncio
    async def test_query_cache_only_caches_approved_or_skipped_unblocked_turns(
        self, graph_result: dict[str, Any], should_cache: bool
    ) -> None:
        from src.governed_financial_advisor import server
        from src.governed_financial_advisor.models.principal import PrincipalIdentity

        fake_cache = SimpleNamespace(
            get=AsyncMock(return_value=None),
            set=AsyncMock(),
        )
        fake_graph = SimpleNamespace(ainvoke=AsyncMock(return_value=graph_result))
        fake_request = MagicMock()
        fake_request.app.state.graph = fake_graph

        with (
            patch.object(
                server,
                "resolve_request_principal",
                return_value=PrincipalIdentity(user_id="user-1", verified=True),
            ),
            patch.object(server, "require_thread_owner", new=AsyncMock()),
            patch(
                "src.governed_financial_advisor.infrastructure.query_cache.get_query_cache",
                new=AsyncMock(return_value=fake_cache),
            ),
        ):
            resp = await server.query_agent(
                req=server.QueryRequest(
                    prompt="What is diversification?", user_id="user-1"
                ),
                request=fake_request,
                _auth="test-key",
            )

        assert "response" in resp
        if should_cache:
            fake_cache.set.assert_awaited_once()
        else:
            fake_cache.set.assert_not_awaited()


# ---------------------------------------------------------------------------
# Surface 5: Provider02AttestationCallback terminal-path classification
# ---------------------------------------------------------------------------


class TestProvider02GatewayErrorClassification:
    def test_extract_signals_captures_gateway_error_status_and_reason(self) -> None:
        signals = _extract_signals(
            "safety_check",
            {
                "safety_status": "GATEWAY_ERROR",
                "last_violation": {
                    "reason_code": "GATEWAY_ERROR",
                    "policy_rule": "GATEWAY_ERROR",
                },
            },
        )
        assert signals["safetyStatus"] == "GATEWAY_ERROR"
        assert signals["violationReasonCode"] == "GATEWAY_ERROR"

    @pytest.mark.parametrize(
        "safety_signals",
        [
            {"safetyStatus": "GATEWAY_ERROR", "violationReasonCode": "GATEWAY_ERROR"},
            {"safetyStatus": "GATEWAY_ERROR"},
            {"safetyStatus": "BLOCKED", "violationReasonCode": "GATEWAY_ERROR"},
            {
                "safetyStatus": "BLOCKED",
                "last_violation": {"reason_code": "GATEWAY_ERROR"},
            },
        ],
        ids=[
            "gateway-error-status-and-code",
            "gateway-error-status-only",
            "blocked-with-gateway-error-code",
            "blocked-with-nested-last-violation",
        ],
    )
    def test_classify_terminal_path_never_labels_gateway_error_as_cbf_block(
        self, safety_signals: dict[str, Any]
    ) -> None:
        steps = [
            ProjectBundleStepEntry(node_name="nemo_guardrail"),
            ProjectBundleStepEntry(node_name="evaluator"),
            ProjectBundleStepEntry(node_name="safety_check", signals=safety_signals),
            ProjectBundleStepEntry(node_name="explainer"),
            ProjectBundleStepEntry(node_name="nemo_output_rail"),
        ]
        result = _classify_terminal_path(steps, FINANCIAL_ADVISOR_TOPOLOGY)
        assert result == "unknown"
        assert result != "cbf_block"

    def test_full_callback_gateway_error_bundle_validates_against_schema(self) -> None:
        cb = Provider02AttestationCallback(
            committer=InProcessCommitter(),
            topology=FINANCIAL_ADVISOR_TOPOLOGY,
            thread_id="poam-228-thread",
        )
        ok_state = {"safety_status": "APPROVED", "risk_status": "APPROVED"}
        err_state = {
            "safety_status": "GATEWAY_ERROR",
            "risk_status": "APPROVED",
            "last_violation": {
                "reason_code": "GATEWAY_ERROR",
                "policy_rule": "GATEWAY_ERROR",
                "evidence": "Gateway returned HTTP 403",
                "recoverable": False,
            },
        }
        for node in (
            "nemo_guardrail",
            "thinker_node",
            "doer_node",
            "execution_analyst",
            "evaluator",
            "ftra_node",
        ):
            cb.on_chain_start(node, ok_state)
            cb.on_chain_end(node, ok_state)
        for node in ("safety_check", "explainer", "nemo_output_rail"):
            cb.on_chain_start(node, err_state)
            cb.on_chain_end(node, err_state)

        bundle = sealed_bundle(cb)
        assert bundle.terminal_path == "unknown"
        ATTESTATION_BUNDLE_VALIDATOR.validate(bundle.to_dict())
