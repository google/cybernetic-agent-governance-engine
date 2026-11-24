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

"""Comprehensive verification suite for POAM-2026-232 (Stages 1-4).

Covers:
1. Stage 1 — Ambiguous HTTP & 200 payload classification across actuator_01/02/03.
2. Stage 2 — Unverified UNKNOWN fiscal hold indexing, broker reconciliation,
   and SLA monitor aged-hold alerting.
3. Stage 3 — Outcome taxonomy split (ActuationIndeterminateError / ActuationRejectedError
   decoupled from SymbolicGovernorViolation, CommitStatus.INDETERMINATE /
   UNSETTLED_DUPLICATE, and /tools/execute non-refusal behavior).
4. Stage 4 — Retry-safe transaction_id derivation independent of LLM tool_call_id
   and terminal advisor indeterminate message / non-retry halting.
"""

from __future__ import annotations

import uuid
from contextlib import ExitStack
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import httpx
import pytest
from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage
from prometheus_client import CollectorRegistry

from src.cage_finance.safety import broker_order_lookup as broker_lookup_mod
from src.cage_finance.safety.broker_order_lookup import (
    BrokerOrderLookupResult,
    BrokerOrderStatus,
    lookup_broker_order_status,
)
from src.cage_finance.safety.fiscal_limit_guard import (
    FiscalLimitGuard,
    ReservationToken,
)
from src.cage_finance.safety.unknown_actuation_reconciler import (
    reconcile_unknown_actuations,
)
from src.cage_finance.tools.tool_provider import (
    FinancialToolProvider,
    execute_trade_action,
)
from src.compliance_bridge.sla_monitor import _check_aged_unknown_actuations
from src.gateway.governance.commit_outcome import (
    INDETERMINATE_STATUSES,
    NON_REFUSAL_STATUSES,
    CommitOutcome,
    CommitStatus,
)
from src.gateway.governance.execution_idempotency import (
    SHARED_CALLER,
    Claim,
    Duplicate,
    ExecutionLedger,
    ExecutionStatus,
    UnsettledDuplicate,
)
from src.gateway.governance.governor.metrics import GovernorMetrics
from src.gateway.governance.routing_seal import SymbolicGovernorViolation
from src.gateway.governance.seams.actuation import (
    ActuationError,
    ActuationIndeterminateError,
    ActuationOutcome,
    ActuationReceipt,
    ActuationRejectedError,
    ExecutionClearance,
)
from src.gateway.governance.seams.quarantine import (
    QuarantineDirective,
    QuarantineTriggerReason,
)
from src.gateway.server import governance_middleware as gm_mod
from src.gateway.server import workload_identity as wid_mod
from src.governed_financial_advisor.graph.governance import tool_guard as tg_mod
from src.governed_financial_advisor.graph.governance.tool_guard import (
    COMMIT_OUTCOMES,
    TRADE_TOOL,
    derive_plan_step_key,
    derive_transaction_id,
    gateway_tool_guard,
)
from src.integrations.actuator_01.response_classifier import (
    ResponseCategory,
    classify_response,
)
from src.integrations.actuator_02.adapter import Actuator02Adapter
from src.integrations.actuator_03.adapter import Actuator03Adapter
from tests.fixtures.trade_inputs import sealed_governance, trade_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]


class _StubSigner:
    is_kms_active = True

    def sign_raw(self, message: bytes) -> bytes:
        return b"\x01" * 64

    async def sign_raw_async(self, message: bytes) -> bytes:
        return self.sign_raw(message)


def _make_clearance(action: str = "execute_trade") -> ExecutionClearance:
    return ExecutionClearance(
        thread_id="thread-test",
        decision="ALLOW",
        decision_path="DIRECT",
        action=action,
        target="account:123",
        operator_urn="urn:actuator_02:op:alice",
        issued_at=1_785_012_000,
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id="550e8400-e29b-41d4-a716-446655440000",
        correlation_id_source="INGRESS_MINTED",
        governance_decision_digest="a" * 64,
        opa_input_digest="b" * 64,
        nonce="c" * 32,
        params={"symbol": "AAPL", "amount": 100.0},
        executor_id="actuator_02",
        routing_seal="eyJhbGciOiJFUzI1NiJ9.eyJub25jZSI6ImMifQ.sigvalue",
        approvals=[
            {
                "approver_urn": "urn:actuator_02:op:alice",
                "approved_at_utc": "2026-08-01T12:00:00Z",
                "approval_signature": "sig-0",
            }
        ],
        required_quorum=1,
        ttl_seconds=30,
    )


def _make_quarantine_directive() -> QuarantineDirective:
    return QuarantineDirective(
        thread_id="thread-test",
        agent_svid="spiffe://test/agent",
        sandbox_id="sbx-1",
        reason=QuarantineTriggerReason.SANDBOX_ESCAPE_ATTEMPT,
        violation_codes=("FTRA_TERMINAL",),
        issued_at=1_785_012_000,
        correlation_id="550e8400-e29b-41d4-a716-446655440000",
        nonce="d" * 32,
        refusal_proof_hash="e" * 64,
    )


def _dummy_response(status_code: int, body: dict[str, Any] | None) -> httpx.Response:
    if body is None:
        return httpx.Response(status_code=status_code, content=b"not-json")
    return httpx.Response(status_code=status_code, json=body)


# ── Stage 1 Tests ──────────────────────────────────────────────────────────


class TestStage1AmbiguousClassification:
    """Ambiguous HTTP and unconfirmed 200 replies map to INDETERMINATE / UNKNOWN."""

    @pytest.mark.parametrize(
        ("body", "expected_cat"),
        [
            (
                {"receipt_id": "r-1", "status": "ACCEPTED"},
                ResponseCategory.ACCEPTED,
            ),
            (
                {"receipt_id": "r-1", "status": "ok"},
                ResponseCategory.ACCEPTED,
            ),
            (
                {"receipt_id": "r-1", "status": "EXECUTED"},
                ResponseCategory.ACCEPTED,
            ),
            (
                {"receipt_id": "r-1", "status": "REJECTED"},
                ResponseCategory.REJECTED_TERMINAL,
            ),
            (
                {"receipt_id": "r-1", "status": "DENIED"},
                ResponseCategory.REJECTED_TERMINAL,
            ),
            (
                {"receipt_id": "r-1"},
                ResponseCategory.INDETERMINATE,
            ),
            (
                {"receipt_id": "r-1", "status": "PENDING_MAYBE"},
                ResponseCategory.INDETERMINATE,
            ),
            (
                {"status": "ACCEPTED"},
                ResponseCategory.INDETERMINATE,
            ),
        ],
    )
    def test_actuator_01_200_status_disambiguation(
        self, body: dict[str, Any], expected_cat: ResponseCategory
    ) -> None:
        res = classify_response(_dummy_response(200, body))
        assert res.category is expected_cat
        assert res.retryable is False

    @pytest.mark.parametrize("status", [408, 409, 421, 422, 429, 500, 502, 503, 504])
    def test_actuator_01_ambiguous_http_is_indeterminate_non_retryable(
        self, status: int
    ) -> None:
        res = classify_response(_dummy_response(status, {"error": "AMBIGUOUS"}))
        assert res.category is ResponseCategory.INDETERMINATE
        assert res.retryable is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [409, 421, 422, 429, 503, 500])
    async def test_actuator_02_ambiguous_statuses_map_to_unknown(
        self, status: int
    ) -> None:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _req: httpx.Response(status, json={"error": "AMBIGUOUS"})
            )
        )
        adapter = Actuator02Adapter(
            endpoint="https://supervisor.example.invalid",
            signer=_StubSigner(),  # type: ignore[arg-type]
            http_client=client,
            require_signed_receipts=False,
        )
        receipt = await adapter.actuate(_make_clearance())
        await client.aclose()
        assert receipt.outcome is ActuationOutcome.UNKNOWN
        assert receipt.accepted is False
        assert receipt.retryable is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [400, 401, 403])
    async def test_actuator_02_explicit_refusal_statuses_map_to_rejected(
        self, status: int
    ) -> None:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _req: httpx.Response(status, json={"error": "BAD_REQUEST"})
            )
        )
        adapter = Actuator02Adapter(
            endpoint="https://supervisor.example.invalid",
            signer=_StubSigner(),  # type: ignore[arg-type]
            http_client=client,
            require_signed_receipts=False,
        )
        receipt = await adapter.actuate(_make_clearance())
        await client.aclose()
        assert receipt.outcome is ActuationOutcome.REJECTED
        assert receipt.accepted is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [409, 421, 422, 429, 503])
    async def test_actuator_03_ambiguous_statuses_map_to_unknown(
        self, status: int
    ) -> None:
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _req: httpx.Response(status, json={"error": "AMBIGUOUS"})
            )
        )
        adapter = Actuator03Adapter(
            endpoint="https://dpu.example.invalid",
            signer=_StubSigner(),  # type: ignore[arg-type]
            http_client=client,
            require_signed_receipts=False,
        )
        receipt = await adapter.quarantine_workload(_make_quarantine_directive())
        await client.aclose()
        assert receipt.outcome is ActuationOutcome.UNKNOWN
        assert receipt.quarantined is False


# ── Stage 2 Tests ──────────────────────────────────────────────────────────


class TestStage2FiscalReclamationAndAlerting:
    """UNVERIFIED UNKNOWN index, broker lookup, reconciliation, and aged SLA alerting."""

    @pytest.mark.asyncio
    async def test_fiscal_guard_unverified_unknown_settle_releases_and_confirms(
        self,
    ) -> None:
        redis = fakeredis.aioredis.FakeRedis()
        guard = FiscalLimitGuard(redis_client=redis, daily_cap_usd=1000.0)
        token_a = await guard.reserve(agent_id="trader-1", amount_usd=400.0)
        token_b = await guard.reserve(agent_id="trader-1", amount_usd=250.0)
        await guard.confirm(token_a)
        await guard.confirm(token_b)

        await guard.record_unverified_unknown(
            "tx-not-executed", token_a, symbol="AAPL", confirmed_at=100.0
        )
        await guard.record_unverified_unknown(
            "tx-filled", token_b, symbol="MSFT", confirmed_at=500.0
        )

        aged = await guard.list_unverified_unknown(older_than_seconds=300.0, now=450.0)
        assert [item.transaction_id for item in aged] == ["tx-not-executed"]
        assert aged[0].amount_usd == 400.0
        assert aged[0].symbol == "AAPL"

        # Confirmed unexecuted -> credits daily spend back.
        assert await guard.settle_unknown("tx-not-executed", executed=False) is True
        assert await guard.settle_unknown("tx-not-executed", executed=False) is False
        assert await guard.current_spend_usd() == pytest.approx(250.0)

        # Confirmed filled -> retains daily spend, removes from unverified index.
        assert await guard.settle_unknown("tx-filled", executed=True) is True
        assert await guard.current_spend_usd() == pytest.approx(250.0)
        assert await guard.list_unverified_unknown() == []

    @pytest.mark.asyncio
    async def test_broker_order_lookup_classification(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(broker_lookup_mod, "_is_mock_broker", lambda: False)
        cfg = {
            "BROKER_API_KEY": "test-key",
            "BROKER_API_SECRET": "test-secret",
            "BROKER_API_URL": "https://broker.example.invalid",
        }
        monkeypatch.setattr(
            broker_lookup_mod.config_manager,
            "get",
            lambda k, default=None: cfg.get(k, default),
        )

        def _client(status: int, payload: Any) -> httpx.AsyncClient:
            return httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda _req: httpx.Response(status, json=payload)
                )
            )

        tx_1 = str(uuid.uuid4())
        tx_2 = str(uuid.uuid4())
        tx_3 = str(uuid.uuid4())
        tx_4 = str(uuid.uuid4())

        async with _client(
            200, {"id": "ord-1", "status": "filled", "filled_qty": "2"}
        ) as c:
            res = await lookup_broker_order_status(tx_1, http_client=c)
        assert res.status is BrokerOrderStatus.FILLED
        assert res.order_id == "ord-1"

        async with _client(404, {"message": "order not found"}) as c:
            res = await lookup_broker_order_status(tx_2, http_client=c)
        assert res.status is BrokerOrderStatus.NOT_EXECUTED

        async with _client(
            200, {"id": "ord-3", "status": "canceled", "filled_qty": "0"}
        ) as c:
            res = await lookup_broker_order_status(tx_3, http_client=c)
        assert res.status is BrokerOrderStatus.NOT_EXECUTED

        async with _client(503, {"error": "unavailable"}) as c:
            res = await lookup_broker_order_status(tx_4, http_client=c)
        assert res.status is BrokerOrderStatus.INDETERMINATE

    @pytest.mark.asyncio
    async def test_reconciler_settles_ledger_fiscal_and_metrics(self) -> None:
        redis = fakeredis.aioredis.FakeRedis()
        guard = FiscalLimitGuard(redis_client=redis, daily_cap_usd=1000.0)
        ledger = ExecutionLedger(redis)
        metrics = GovernorMetrics(CollectorRegistry())

        for tx_id, amt, ts in [
            ("tx-filled", 100.0, 100.0),
            ("tx-unexecuted", 200.0, 100.0),
            ("tx-stuck-aged", 300.0, 50.0),
        ]:
            claim = await ledger.claim("execute_trade", SHARED_CALLER, tx_id)
            assert isinstance(claim, Claim)
            await ledger.record_outcome(
                claim, ExecutionStatus.UNKNOWN, "outcome unknown"
            )
            tok = await guard.reserve(agent_id="trader-1", amount_usd=amt)
            await guard.confirm(tok)
            await guard.record_unverified_unknown(
                tx_id, tok, symbol="AAPL", confirmed_at=ts
            )

        lookup_map = {
            "tx-filled": BrokerOrderLookupResult(
                BrokerOrderStatus.FILLED, order_id="brk-1"
            ),
            "tx-unexecuted": BrokerOrderLookupResult(
                BrokerOrderStatus.NOT_EXECUTED, detail="404"
            ),
            "tx-stuck-aged": BrokerOrderLookupResult(
                BrokerOrderStatus.INDETERMINATE, detail="503"
            ),
        }

        async def _lookup(tx_id: str) -> BrokerOrderLookupResult:
            return lookup_map[tx_id]

        aged_alerts: list[list[Any]] = []
        report = await reconcile_unknown_actuations(
            guard,
            execution_ledger=ledger,
            lookup_fn=_lookup,
            max_age_seconds=300.0,
            governor_metrics=metrics,
            on_aged_unresolved=lambda items: aged_alerts.append(items),
            now=500.0,
        )

        assert report.checked == 3
        assert report.settled_executed == ("tx-filled",)
        assert report.settled_reclaimed == ("tx-unexecuted",)
        assert report.still_indeterminate == ("tx-stuck-aged",)
        assert len(report.aged_unresolved) == 1
        assert len(aged_alerts) == 1
        assert aged_alerts[0][0].transaction_id == "tx-stuck-aged"
        assert await guard.current_spend_usd() == pytest.approx(400.0)

        # Ledger entries were transitioned properly:
        filled_replay = await ledger.claim("execute_trade", SHARED_CALLER, "tx-filled")
        assert isinstance(filled_replay, Duplicate)
        assert filled_replay.status is ExecutionStatus.EXECUTED

        released_replay = await ledger.claim(
            "execute_trade", SHARED_CALLER, "tx-unexecuted"
        )
        assert isinstance(released_replay, Duplicate)
        assert released_replay.status is ExecutionStatus.BLOCKED

        still_unknown = await ledger.claim(
            "execute_trade", SHARED_CALLER, "tx-stuck-aged"
        )
        assert isinstance(still_unknown, Duplicate)
        assert still_unknown.status is ExecutionStatus.UNKNOWN

    @pytest.mark.asyncio
    async def test_sla_monitor_alerts_only_when_aged_unknown_exceeds_threshold(
        self,
    ) -> None:
        redis = fakeredis.aioredis.FakeRedis()
        guard = FiscalLimitGuard(redis_client=redis, daily_cap_usd=1000.0)
        tok = ReservationToken(
            reservation_id="res-1",
            agent_id="trader-1",
            amount_usd=100.0,
            amount_cents=10000,
            reserved_at=100.0,
            window_key="fiscal:daily_limit:2026-11-24",
            cap_usd=1000.0,
            running_total_usd=100.0,
            rejected=False,
            ttl_seconds=300,
        )
        await guard.record_unverified_unknown(
            "tx-aged-1", tok, symbol="AAPL", confirmed_at=100.0
        )

        notifier = MagicMock()
        notifier.send_critical_alert = AsyncMock(return_value=True)

        with patch(
            "src.compliance_bridge.sla_monitor.create_notifier",
            return_value=notifier,
        ):
            # Within threshold (150s < 300s) -> no alert.
            none_finding = await _check_aged_unknown_actuations(
                now=250.0, redis_client=redis
            )
            assert none_finding is None
            notifier.send_critical_alert.assert_not_awaited()

            # Past threshold (450s - 100s = 350s >= 300s) -> critical SC-4 alert.
            finding = await _check_aged_unknown_actuations(
                now=450.0, redis_client=redis
            )

        assert finding is not None
        assert finding.control_id == "SC-4"
        assert finding.assessment_status == "aged_unknown_actuations"
        assert finding.remarks is not None and "tx-aged-1" in finding.remarks
        notifier.send_critical_alert.assert_awaited_once()


# ── Stage 3 Tests ──────────────────────────────────────────────────────────


class TestStage3OutcomeSplitAndMcpServer:
    """Actuation errors do not inherit SymbolicGovernorViolation and don't increment refusal counters."""

    def test_exception_hierarchy_decoupled_from_governor_violation(self) -> None:
        indet = ActuationIndeterminateError("timeout", action="execute_trade")
        rejected = ActuationRejectedError("bad order", action="execute_trade")

        assert isinstance(indet, ActuationError)
        assert isinstance(rejected, ActuationError)
        assert not isinstance(indet, SymbolicGovernorViolation)
        assert not isinstance(rejected, SymbolicGovernorViolation)
        assert indet.outcome is ActuationOutcome.UNKNOWN
        assert rejected.outcome is ActuationOutcome.REJECTED
        assert CommitStatus.INDETERMINATE in INDETERMINATE_STATUSES
        assert CommitStatus.UNSETTLED_DUPLICATE in INDETERMINATE_STATUSES
        assert NON_REFUSAL_STATUSES == INDETERMINATE_STATUSES

    @pytest.mark.asyncio
    async def test_execute_trade_action_indexes_unknown_hold_after_settle(self) -> None:
        redis = fakeredis.aioredis.FakeRedis()
        fiscal_guard = FiscalLimitGuard(redis_client=redis, daily_cap_usd=1000.0)
        governor = trade_governor()
        held_tok = ReservationToken(
            reservation_id="res-hold-1",
            agent_id="trader-1",
            amount_usd=100.0,
            amount_cents=10000,
            reserved_at=100.0,
            window_key="fiscal:daily_limit:2026-11-24",
            cap_usd=1000.0,
            running_total_usd=100.0,
            rejected=False,
            ttl_seconds=300,
        )
        governor.held_receipt = MagicMock(return_value=held_tok)
        governor.components.domain_tiers = (
            SimpleNamespace(tier_name="fiscal", guard=fiscal_guard),
        )
        tx_id = str(uuid.uuid4())
        unknown_receipt = ActuationReceipt(
            accepted=False,
            receipt_id=None,
            session_uuid="s-1",
            raw_receipt=None,
            findings=[{"code": "HTTP_503", "detail": "upstream 503"}],
            retryable=False,
            outcome=ActuationOutcome.UNKNOWN,
        )

        with ExitStack() as stack:
            stack.enter_context(
                patch(
                    "src.cage_finance.tools.tool_provider.enforce_governance",
                    new_callable=AsyncMock,
                    side_effect=sealed_governance("seal-1"),
                )
            )
            stack.enter_context(
                patch(
                    "src.gateway.governance.routing_seal.verify_and_consume_seal",
                    AsyncMock(),
                )
            )
            stack.enter_context(
                patch("src.gateway.infrastructure.redis_client.redis_client", None)
            )
            stack.enter_context(
                patch(
                    "src.cage_finance.tools.tool_provider._broker_actuator.actuate",
                    AsyncMock(return_value=unknown_receipt),
                )
            )
            with pytest.raises(ActuationIndeterminateError):
                await execute_trade_action(
                    symbol="AAPL",
                    amount=100.0,
                    currency="USD",
                    transaction_id=tx_id,
                    governor=governor,
                )

        unverified = await fiscal_guard.list_unverified_unknown()
        assert len(unverified) == 1
        assert unverified[0].transaction_id == tx_id
        assert unverified[0].amount_usd == 100.0

    @pytest.mark.asyncio
    async def test_execute_trade_tool_returns_structured_indeterminate_and_duplicate(
        self,
    ) -> None:
        registered: dict[str, Any] = {}

        class _FakeServer:
            def tool(self, name: str | None = None, **_kw: Any) -> Any:
                def _decorator(fn: Any) -> Any:
                    registered[name or fn.__name__] = fn
                    return fn

                return _decorator

        FinancialToolProvider().register_tools(_FakeServer(), trade_governor())  # type: ignore[arg-type]
        tool_fn = registered["execute_trade_action"]

        with patch(
            "src.cage_finance.tools.tool_provider.execute_trade_action",
            new_callable=AsyncMock,
            side_effect=ActuationIndeterminateError("http 503", action="execute_trade"),
        ):
            call_res = await tool_fn(symbol="AAPL", amount=10.0, currency="USD")
        assert call_res.isError is True
        assert call_res.structuredContent is not None
        assert call_res.structuredContent["status"] == "INDETERMINATE"

        with patch(
            "src.cage_finance.tools.tool_provider.execute_trade_action",
            new_callable=AsyncMock,
            side_effect=UnsettledDuplicate("UNKNOWN: pending reconciliation"),
        ):
            dup_res = await tool_fn(symbol="AAPL", amount=10.0, currency="USD")
        assert dup_res.isError is True
        assert dup_res.structuredContent is not None
        assert dup_res.structuredContent["status"] == "UNSETTLED_DUPLICATE"

    def test_mcp_tools_execute_indeterminate_skips_mark_request_refused(self) -> None:
        from src.gateway.server import mcp_tool_server as mts

        async def _raise_indeterminate(**_kw: Any) -> Any:
            raise ActuationIndeterminateError("503 after wire", action="execute_trade")

        async def _raise_duplicate(**_kw: Any) -> Any:
            raise UnsettledDuplicate("UNKNOWN: pending")

        async def _return_mcp_indet(**_kw: Any) -> Any:
            from mcp.types import CallToolResult, TextContent

            return CallToolResult(
                content=[TextContent(type="text", text="uncertain")],
                structuredContent=CommitOutcome(
                    CommitStatus.INDETERMINATE, "uncertain"
                ).to_wire(),
                isError=True,
            )

        async def _return_mcp_rejected(**_kw: Any) -> Any:
            from mcp.types import CallToolResult, TextContent

            msg = "Actuation rejected: SAFETY_INTERRUPT: smoke_interrupt"
            return CallToolResult(
                content=[TextContent(type="text", text=msg)],
                structuredContent=CommitOutcome(CommitStatus.REFUSED, msg).to_wire(),
                isError=True,
            )

        fake_tools = [
            SimpleNamespace(name="t_indet", fn=_raise_indeterminate),
            SimpleNamespace(name="t_dup", fn=_raise_duplicate),
            SimpleNamespace(name="t_mcp", fn=_return_mcp_indet),
            SimpleNamespace(name="t_mcp_rej", fn=_return_mcp_rejected),
        ]
        trusted_id = "cage-advisor-sa.cage-governance.serviceaccount.identity.linkerd.cluster.local"
        policy = wid_mod.IdentityPolicy(
            trusted=frozenset({trusted_id}),
            canary=frozenset(),
        )

        with (
            patch.object(wid_mod, "extract_client_identity", return_value=trusted_id),
            patch.object(wid_mod, "load_identity_policy", return_value=policy),
            patch.object(mts, "refuse_if_quarantined", AsyncMock(return_value=None)),
            patch.object(mts, "_check_rate_limit", AsyncMock(return_value=True)),
            patch.object(
                gm_mod, "sanitize_mcp_tool_response", AsyncMock(return_value=None)
            ),
            patch.object(mts, "mark_request_refused") as mark_refused,
            patch.object(mts.mcp._tool_manager, "list_tools", return_value=fake_tools),
        ):
            client = TestClient(mts.app)
            for tool_name, expected_status in [
                ("t_indet", "INDETERMINATE"),
                ("t_dup", "UNSETTLED_DUPLICATE"),
                ("t_mcp", "INDETERMINATE"),
            ]:
                resp = client.post(
                    "/tools/execute",
                    json={"tool_name": tool_name, "params": {}},
                )
                assert resp.status_code == 200
                data = resp.json()
                assert data["status"] == "ERROR"
                assert data["error"]
                assert data["actuation_outcome"] == "UNKNOWN"
                assert data["may_have_executed"] is True
                assert data["outcome"]["status"] == expected_status
            mark_refused.assert_not_called()

            rej_resp = client.post(
                "/tools/execute",
                json={"tool_name": "t_mcp_rej", "params": {}},
            )
            assert rej_resp.status_code == 200
            rej_data = rej_resp.json()
            assert rej_data["status"] == "ERROR"
            assert "Actuation rejected" in rej_data["error"]
            assert rej_data["outcome"]["status"] == "REFUSED"
            mark_refused.assert_called_once()


# ── Stage 4 Tests ──────────────────────────────────────────────────────────


class TestStage4RetrySafeIdempotencyAndAdvisorHalting:
    """Retry-safe plan/intent derivation & non-retryable terminal advisor outcome."""

    def test_derive_transaction_id_ignores_volatile_tool_call_id(self) -> None:
        args_a = {"symbol": "AAPL", "amount": 100.0, "side": "BUY", "currency": "USD"}
        plan = {
            "steps": [
                {
                    "action": "execute_trade",
                    "symbol": "AAPL",
                    "amount": 100.0,
                    "side": "BUY",
                }
            ]
        }
        k1 = derive_plan_step_key(args_a, plan_steps=plan["steps"], occurrence=0)
        k2 = derive_plan_step_key(dict(args_a), plan_steps=plan["steps"], occurrence=0)
        assert k1 == k2

        tx1 = derive_transaction_id(k1, thread_id="thread-abc", message_id="msg-1")
        tx2 = derive_transaction_id(k2, thread_id="thread-abc", message_id="msg-2")
        assert tx1 == tx2
        assert uuid.UUID(tx1).version == 5

    @pytest.mark.asyncio
    async def test_advisor_tool_guard_halts_on_indeterminate_with_reconcile_message(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen_txns: list[str] = []

        async def _node(state: dict[str, Any]) -> dict[str, Any]:
            call = state["messages"][-1].tool_calls[0]
            seen_txns.append(call["args"]["transaction_id"])
            return {
                "messages": [],
                COMMIT_OUTCOMES: {
                    call["id"]: CommitOutcome(
                        CommitStatus.INDETERMINATE,
                        "Execution outcome is indeterminate",
                    )
                },
            }

        monkeypatch.setattr(
            tg_mod,
            "get_config",
            lambda: {"configurable": {"thread_id": "thread-reconcile"}},
        )
        guarded = gateway_tool_guard("execute_trade", approvable=True)(_node)
        state = {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": TRADE_TOOL,
                            "args": {
                                "symbol": "AAPL",
                                "amount": 100.0,
                                "side": "BUY",
                                "currency": "USD",
                            },
                            "id": "llm-call-first",
                        }
                    ],
                    id="ai-first",
                )
            ],
            "deferred_id": "def-1",
            "approval_decision": {"approved": True},
        }
        out = await guarded(state)
        assert out["governance_status"] == "DENIED"
        msg = out["messages"][0].content
        assert "could not be confirmed" in msg
        assert "Do not submit it again until it has been reconciled" in msg
        assert "Submit a new request" not in msg

        # Even if caller/LLM replays with a fresh tool_call_id, transaction_id is identical.
        replay_state = {
            **state,
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": TRADE_TOOL,
                            "args": {
                                "symbol": "AAPL",
                                "amount": 100.0,
                                "side": "BUY",
                                "currency": "USD",
                            },
                            "id": "llm-call-second-fresh-id",
                        }
                    ],
                    id="ai-second",
                )
            ],
        }
        await guarded(replay_state)
        assert len(seen_txns) == 2
        assert seen_txns[0] == seen_txns[1]


class TestEndToEndUnknownActuationLifecycle:
    """POAM-2026-232 Closure Criterion 3: single trade across Stages 1-4."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("broker_filled", [False, True])
    async def test_e2e_single_trade_through_all_four_stages(
        self,
        broker_filled: bool,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from src.gateway.server import mcp_tool_server as mts

        redis = fakeredis.aioredis.FakeRedis()
        fiscal_guard = FiscalLimitGuard(redis_client=redis, daily_cap_usd=1000.0)
        ledger = ExecutionLedger(redis)
        metrics = GovernorMetrics(CollectorRegistry())

        governor = trade_governor()
        governor.components.execution_ledger = ledger
        governor.components.metrics = metrics
        governor.components.domain_tiers = (
            SimpleNamespace(tier_name="fiscal", guard=fiscal_guard),
        )

        # Stage 2/3 setup: simulate real fiscal reserve + settle(executed=True) hold on UNKNOWN.
        held_tokens: dict[str, ReservationToken] = {}

        async def _enforce_with_reserve(
            gov: Any, action: str, params: dict[str, Any], *_args: Any, **_kw: Any
        ) -> Any:
            tok = await fiscal_guard.reserve(
                agent_id="trader-1",
                amount_usd=float(params["amount"]),
            )
            seal = f"seal-{params['transaction_id']}"
            held_tokens[seal] = tok
            return sealed_governance(seal)(gov, action, params, **_kw)

        async def _settle(seal: str, *, executed: bool) -> list[Any]:
            tok = held_tokens.get(seal)
            if tok is not None and executed:
                await fiscal_guard.confirm(tok)
            return []

        governor.held_receipt = MagicMock(
            side_effect=lambda seal, tier: (
                held_tokens.get(seal) if tier == "fiscal" else None
            )
        )
        governor.settle = AsyncMock(side_effect=_settle)

        # Register the real MCP tool wrapper on a mock FastMCP tool manager.
        registered: dict[str, Any] = {}

        class _FakeServer:
            def tool(self, name: str | None = None, **_kw: Any) -> Any:
                def _decorator(fn: Any) -> Any:
                    registered[name or fn.__name__] = fn
                    return fn

                return _decorator

        FinancialToolProvider().register_tools(_FakeServer(), governor)  # type: ignore[arg-type]
        tool_fn = registered["execute_trade_action"]
        fake_tools = [SimpleNamespace(name=TRADE_TOOL, fn=tool_fn)]
        trusted_id = "cage-advisor-sa.cage-governance.serviceaccount.identity.linkerd.cluster.local"
        policy = wid_mod.IdentityPolicy(
            trusted=frozenset({trusted_id}), canary=frozenset()
        )

        # Stage 1: actuator transport/HTTP ambiguity produces ActuationOutcome.UNKNOWN.
        timeout_receipt = ActuationReceipt(
            accepted=False,
            receipt_id=None,
            session_uuid="sess-timeout",
            raw_receipt=None,
            findings=[
                {"code": "BROKER_TRANSPORT_INDETERMINATE", "detail": "read timeout"}
            ],
            retryable=False,
            outcome=ActuationOutcome.UNKNOWN,
        )

        async def _gateway_node(state: dict[str, Any]) -> dict[str, Any]:
            call = state["messages"][-1].tool_calls[0]
            with (
                patch.object(
                    wid_mod, "extract_client_identity", return_value=trusted_id
                ),
                patch.object(wid_mod, "load_identity_policy", return_value=policy),
                patch.object(
                    mts, "refuse_if_quarantined", AsyncMock(return_value=None)
                ),
                patch.object(mts, "_check_rate_limit", AsyncMock(return_value=True)),
                patch.object(
                    gm_mod, "sanitize_mcp_tool_response", AsyncMock(return_value=None)
                ),
                patch.object(
                    mts.mcp._tool_manager, "list_tools", return_value=fake_tools
                ),
                patch(
                    "src.cage_finance.tools.tool_provider.enforce_governance",
                    new_callable=AsyncMock,
                    side_effect=_enforce_with_reserve,
                ),
                patch(
                    "src.cage_finance.tools.tool_provider.enforce_approved_governance",
                    new_callable=AsyncMock,
                    side_effect=_enforce_with_reserve,
                ),
                patch(
                    "src.gateway.governance.routing_seal.verify_and_consume_seal",
                    AsyncMock(),
                ),
                patch("src.gateway.infrastructure.redis_client.redis_client", None),
                patch(
                    "src.cage_finance.tools.tool_provider._broker_actuator.actuate",
                    AsyncMock(return_value=timeout_receipt),
                ),
            ):
                client = TestClient(mts.app)
                resp = client.post(
                    "/tools/execute",
                    json={"tool_name": TRADE_TOOL, "params": dict(call["args"])},
                )
            body = resp.json()
            assert body["actuation_outcome"] == "UNKNOWN"
            assert body["may_have_executed"] is True
            return {
                "messages": [],
                COMMIT_OUTCOMES: {
                    call["id"]: CommitOutcome.from_wire(body["outcome"]),
                },
            }

        monkeypatch.setattr(
            tg_mod,
            "get_config",
            lambda: {"configurable": {"thread_id": "thread-e2e-232"}},
        )
        guarded = gateway_tool_guard("execute_trade", approvable=True)(_gateway_node)

        first_state = {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": TRADE_TOOL,
                            "args": {
                                "symbol": "AAPL",
                                "amount": 250.0,
                                "side": "buy",
                                "currency": "USD",
                            },
                            "id": "call-e2e-1",
                        }
                    ],
                    id="ai-e2e-1",
                )
            ],
            "deferred_id": "def-e2e-1",
            "approval_decision": {"approved": True},
        }
        with patch.object(mts, "mark_request_refused") as mark_refused:
            first_out = await guarded(first_state)
            mark_refused.assert_not_called()

        # Stage 4: advisor halted without loop, transaction_id bound, fiscal held.
        assert first_out["governance_status"] == "DENIED"
        assert "Do not submit it again until it has been reconciled" in (
            first_out["messages"][0].content
        )
        assert await fiscal_guard.current_spend_usd() == pytest.approx(250.0)
        unverified = await fiscal_guard.list_unverified_unknown()
        assert len(unverified) == 1
        tx_id = unverified[0].transaction_id

        # Simulated LLM retry with fresh tool_call_id collides deterministically as UNSETTLED_DUPLICATE.
        retry_state = {
            **first_state,
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": TRADE_TOOL,
                            "args": {
                                "symbol": "AAPL",
                                "amount": 250.0,
                                "side": "buy",
                                "currency": "USD",
                            },
                            "id": "call-e2e-2-fresh-id",
                        }
                    ],
                    id="ai-e2e-2",
                )
            ],
        }
        dup_out = await guarded(retry_state)
        assert dup_out["governance_status"] == "DENIED"
        assert "Do not submit it again until it has been reconciled" in (
            dup_out["messages"][0].content
        )
        # Re-claim check confirms key is still UNKNOWN before reconciliation.
        pre_reconcile = await ledger.claim("execute_trade", SHARED_CALLER, tx_id)
        assert isinstance(pre_reconcile, Duplicate)
        assert pre_reconcile.status is ExecutionStatus.UNKNOWN

        # Stage 2: broker lookup reconciliation resolves non-fill (reclaim) vs fill (retain).
        monkeypatch.setattr(broker_lookup_mod, "_is_mock_broker", lambda: False)
        cfg = {
            "BROKER_API_KEY": "test-key",
            "BROKER_API_SECRET": "test-secret",
            "BROKER_API_URL": "https://broker.example.invalid",
        }
        monkeypatch.setattr(
            broker_lookup_mod.config_manager,
            "get",
            lambda k, default=None: cfg.get(k, default),
        )

        def _lookup_handler(_req: httpx.Request) -> httpx.Response:
            if broker_filled:
                return httpx.Response(
                    200, json={"id": "ord-e2e", "status": "filled", "filled_qty": "1"}
                )
            return httpx.Response(404, json={"message": "order not found"})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_lookup_handler)
        ) as http_client:
            report = await reconcile_unknown_actuations(
                fiscal_guard,
                execution_ledger=ledger,
                lookup_fn=lambda tid: lookup_broker_order_status(
                    tid, http_client=http_client
                ),
                governor_metrics=metrics,
            )

        post_reconcile = await ledger.claim("execute_trade", SHARED_CALLER, tx_id)
        assert isinstance(post_reconcile, Duplicate)
        if broker_filled:
            assert report.settled_executed == (tx_id,)
            assert await fiscal_guard.current_spend_usd() == pytest.approx(250.0)
            assert post_reconcile.status is ExecutionStatus.EXECUTED
        else:
            assert report.settled_reclaimed == (tx_id,)
            assert await fiscal_guard.current_spend_usd() == pytest.approx(0.0)
            assert post_reconcile.status is ExecutionStatus.BLOCKED
        assert await fiscal_guard.list_unverified_unknown() == []
