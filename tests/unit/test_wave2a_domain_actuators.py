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

"""Comprehensive Wave 2A verification suite (DA-01, DA-02, DA-06, DA-11, DA-13 Python)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import httpx
import pytest

from src.cage_finance.actuators.broker_actuator import BrokerActuator
from src.cage_finance.models.trade_order import TradeOrder
from src.cage_finance.safety.bounding.contracts import (
    contract_b1_max_notional,
    contract_b2_drawdown_breaker,
    contract_b6_hitl_high_impact,
)
from src.cage_finance.safety.fiscal_limit_guard import FiscalLimitGuard
from src.cage_finance.tiers.causal_tier import CausalTierPlugin
from src.cage_finance.tools import trade_executor
from src.cage_finance.tools.tool_provider import (
    _approval_covers_trade,
    execute_trade_action,
)
from src.cage_finance.tools.trade_executor import (
    IndeterminateExecutionError,
    PreWireRejectionError,
)
from src.gateway.governance.execution_idempotency import (
    SHARED_CALLER,
    ExecutionLedger,
    ExecutionStatus,
)
from src.gateway.governance.routing_seal import (
    SymbolicGovernorViolation,
    generate_seal,
    seal_digest,
)
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ExecutionClearance,
)
from tests.fixtures.trade_inputs import sealed_governance, trade_governor

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture(autouse=True)
def _allow_hmac_test_seals(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CAGE_SEAL_STRICT_MODE", "false")


async def _make_trade_clearance(
    params: dict[str, Any] | None = None,
    *,
    action: str = "execute_trade",
    seal: str | None = None,
    digest: str | None = None,
) -> ExecutionClearance:
    txn_id = str(uuid.uuid4())
    payload = params or {
        "symbol": "AAPL",
        "amount": 250.0,
        "amount_minor": 25000,
        "currency": "USD",
        "side": "buy",
        "confidence": 0.99,
        "idempotency_key": txn_id,
    }
    minted_seal = (
        seal
        if seal is not None
        else await generate_seal(action, payload, record_hash="e" * 64)
    )
    gov_digest = digest if digest is not None else seal_digest(minted_seal)
    tid = str(uuid.uuid4())
    return ExecutionClearance(
        thread_id=tid,
        decision="ALLOW",
        decision_path="DIRECT",
        action=action,
        target="AAPL",
        operator_urn="trader_01",
        issued_at=int(time.time()),
        issued_at_provenance="CONSTRUCTION_TIME",
        correlation_id=txn_id,
        correlation_id_source="INGRESS_MINTED",
        governance_decision_digest=gov_digest,
        opa_input_digest=hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest(),
        nonce=uuid.uuid4().hex[:32],
        params=payload,
        executor_id="cage_finance_broker",
        target_route="local://default",
        consequence_ceiling="HIGH_FINANCIAL",
        approvals=[],
        required_quorum=0,
        routing_seal=minted_seal,
    )


def _broker_config() -> MagicMock:
    cfg = MagicMock()
    cfg.get.side_effect = lambda key, default=None: {
        "BROKER_API_KEY": "ak-test",
        "BROKER_API_SECRET": "as-test",
        "BROKER_API_URL": "https://broker.example",
    }.get(key, default)
    return cfg


class TestDA01BrokerWirePhaseAndSettlement:
    """[DA-01] Pre-wire vs post-wire broker error classification & conservative settlement."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "transport_exc",
        [
            httpx.ConnectTimeout("tcp syn timeout"),
            httpx.ConnectError("dns/tls refused"),
            httpx.PoolTimeout("connection pool exhausted"),
        ],
    )
    async def test_pre_wire_connect_failures_raise_pre_wire_rejection(
        self, transport_exc: Exception
    ) -> None:
        order = TradeOrder(
            symbol="AAPL",
            amount=100.0,
            currency="USD",
            side="buy",
            confidence=0.99,
            idempotency_key=str(uuid.uuid4()),
        )
        seal = await generate_seal(
            "execute_trade", order.model_dump(exclude_none=True), record_hash="e" * 64
        )

        def _fail_connect(request: httpx.Request) -> httpx.Response:
            raise transport_exc

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(_fail_connect)
        ) as client:
            with (
                patch.object(trade_executor, "_USE_MOCK_BROKER", False),
                patch.object(trade_executor, "config_manager", _broker_config()),
                patch.object(
                    trade_executor, "_redis_get", AsyncMock(return_value=None)
                ),
            ):
                with pytest.raises(PreWireRejectionError) as exc_info:
                    await trade_executor.execute_trade(
                        order, routing_seal=seal, http_client=client
                    )
        assert exc_info.value.retryable is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status_code", [400, 401, 403])
    async def test_deterministic_4xx_broker_refusals_map_to_rejected(
        self, status_code: int
    ) -> None:
        clearance = await _make_trade_clearance()
        actuator = BrokerActuator(ledger=MagicMock())

        def _reject(_req: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code, json={"message": "rejected"})

        real_async_client = httpx.AsyncClient
        with (
            patch.object(trade_executor, "_USE_MOCK_BROKER", False),
            patch.object(trade_executor, "config_manager", _broker_config()),
            patch.object(trade_executor, "_redis_get", AsyncMock(return_value=None)),
            patch(
                "src.cage_finance.tools.trade_executor.httpx.AsyncClient",
                side_effect=lambda *a, **kw: real_async_client(
                    transport=httpx.MockTransport(_reject)
                ),
            ),
        ):
            receipt = await actuator.actuate(clearance)

        assert receipt.accepted is False
        assert receipt.outcome is ActuationOutcome.REJECTED
        assert receipt.retryable is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "failure_mode",
        [
            "read_timeout",
            "write_timeout",
            "remote_protocol_error",
            "http_422",
            "http_500",
            "http_502",
            "http_503",
            "http_504",
            "http_429",
            "malformed_json_200",
            "missing_id_200",
        ],
    )
    async def test_post_wire_failures_map_to_unknown_and_non_retryable(
        self, failure_mode: str
    ) -> None:
        order = TradeOrder(
            symbol="MSFT",
            amount=500.0,
            currency="USD",
            side="buy",
            confidence=0.99,
            idempotency_key=str(uuid.uuid4()),
        )
        seal = await generate_seal(
            "execute_trade", order.model_dump(exclude_none=True), record_hash="e" * 64
        )

        def _handler(request: httpx.Request) -> httpx.Response:
            if failure_mode == "read_timeout":
                raise httpx.ReadTimeout("timed out waiting for 200", request=request)
            if failure_mode == "write_timeout":
                raise httpx.WriteTimeout("timed out mid-body", request=request)
            if failure_mode == "remote_protocol_error":
                raise httpx.RemoteProtocolError("peer reset", request=request)
            if failure_mode.startswith("http_"):
                code = int(failure_mode.split("_")[1])
                return httpx.Response(code, content=b"upstream error")
            if failure_mode == "malformed_json_200":
                return httpx.Response(200, content=b"{truncated-json")
            return httpx.Response(200, json={"status": "accepted_without_id"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
            with (
                patch.object(trade_executor, "_USE_MOCK_BROKER", False),
                patch.object(trade_executor, "config_manager", _broker_config()),
                patch.object(
                    trade_executor, "_redis_get", AsyncMock(return_value=None)
                ),
            ):
                with pytest.raises(IndeterminateExecutionError) as exc_info:
                    await trade_executor.execute_trade(
                        order, routing_seal=seal, http_client=client
                    )
        assert exc_info.value.retryable is False

        # Verify BrokerActuator maps IndeterminateExecutionError -> ActuationOutcome.UNKNOWN
        clearance = await _make_trade_clearance()
        actuator = BrokerActuator(ledger=MagicMock())
        with patch(
            "src.cage_finance.actuators.broker_actuator.execute_trade",
            AsyncMock(side_effect=exc_info.value),
        ):
            receipt = await actuator.actuate(clearance)
        assert receipt.accepted is False
        assert receipt.outcome is ActuationOutcome.UNKNOWN
        assert receipt.retryable is False
        assert receipt.may_have_executed is True

    @pytest.mark.asyncio
    async def test_cancelled_error_mid_actuation_confirms_seal_and_leaves_ledger_unknown(
        self,
    ) -> None:
        redis = fakeredis.aioredis.FakeRedis()
        ledger = ExecutionLedger(redis)
        governor = trade_governor()
        governor.components.execution_ledger = ledger
        txn_id = str(uuid.uuid4())
        seal = "seal-cancel-midflight"

        async def _cancel_in_flight(_clearance: ExecutionClearance) -> Any:
            raise asyncio.CancelledError()

        with (
            patch(
                "src.cage_finance.tools.tool_provider.enforce_governance",
                AsyncMock(side_effect=sealed_governance(seal)),
            ),
            patch(
                "src.gateway.governance.routing_seal.verify_and_consume_seal",
                AsyncMock(return_value=None),
            ),
            patch(
                "src.cage_finance.tools.tool_provider._broker_actuator.actuate",
                side_effect=_cancel_in_flight,
            ),
            patch("src.gateway.infrastructure.redis_client.redis_client", None),
        ):
            with pytest.raises(asyncio.CancelledError):
                await execute_trade_action(
                    governor=governor,
                    idempotency_key=txn_id,
                    symbol="AAPL",
                    amount=100.0,
                    currency="USD",
                )

        # Reservation MUST be confirmed (executed=True), never released on mid-flight cancel!
        governor.settle.assert_awaited_once_with(seal, executed=True)
        # Re-claiming the same idempotency_key must return Duplicate(status=UNKNOWN)
        from src.gateway.governance.execution_idempotency import Duplicate

        dup = await ledger.claim("execute_trade", SHARED_CALLER, txn_id)
        assert isinstance(dup, Duplicate)
        assert dup.status is ExecutionStatus.UNKNOWN


class TestDA02BrokerActuatorCryptographicSealVerification:
    """[DA-02] BrokerActuator verifies seal digest binding and cryptographic HMAC/signature."""

    @pytest.mark.asyncio
    async def test_broker_actuator_rejects_forged_seal_and_digest_tampering(
        self,
    ) -> None:
        actuator = BrokerActuator(ledger=MagicMock())

        # 1. Forged seal string whose SHA-256 matches governance_decision_digest
        forged_seal = "forged-seal-string"
        c_forged = await _make_trade_clearance(
            seal=forged_seal, digest=seal_digest(forged_seal)
        )
        r_forged = await actuator.actuate(c_forged)
        assert r_forged.accepted is False
        assert r_forged.outcome is ActuationOutcome.REJECTED
        assert r_forged.findings[0]["code"] == "INVALID_ROUTING_SEAL"

        # 2. Valid seal bound to AAPL $250 replayed with mutated params ($250,000)
        valid_c = await _make_trade_clearance()
        tampered_params = {
            **valid_c.params,
            "amount": 250000.0,
            "amount_minor": 25000000,
        }
        c_tampered = await _make_trade_clearance(
            params=tampered_params,
            seal=valid_c.routing_seal,
            digest=valid_c.governance_decision_digest,
        )
        r_tampered = await actuator.actuate(c_tampered)
        assert r_tampered.accepted is False
        assert r_tampered.outcome is ActuationOutcome.REJECTED
        assert r_tampered.findings[0]["code"] == "INVALID_ROUTING_SEAL"

        # 3. Digest mismatch
        c_bad_digest = await _make_trade_clearance(digest="f" * 64)
        r_bad_digest = await actuator.actuate(c_bad_digest)
        assert r_bad_digest.accepted is False
        assert r_bad_digest.outcome is ActuationOutcome.REJECTED
        assert r_bad_digest.findings[0]["code"] == "SEAL_DIGEST_MISMATCH"


class TestDA11AndDA13DomainValidationHardening:
    """[DA-11] bool/zero/inf/mismatch rejection & [DA-13] CausalTierPlugin.claims_action."""

    def test_causal_tier_claims_both_execute_trade_and_execute_trade_bounded(
        self,
    ) -> None:
        tier = CausalTierPlugin(causal_gatekeeper=MagicMock())
        assert tier.claims_action("execute_trade", {}) is True
        assert tier.claims_action("execute_trade_bounded", {}) is True
        assert tier.claims_action("market_analysis", {}) is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad_val", [True, False, 0, 0.0, -10.0, 0.001, math.nan, math.inf]
    )
    async def test_fiscal_limit_guard_reserve_rejects_bool_zero_subcent_and_non_finite(
        self, bad_val: Any
    ) -> None:
        redis = fakeredis.aioredis.FakeRedis()
        guard = FiscalLimitGuard(redis_client=redis, daily_cap_usd=50_000.0)
        with pytest.raises(ValueError):
            await guard.reserve(agent_id="a1", amount_usd=bad_val)
        assert await guard.would_accept(bad_val) is False

    @pytest.mark.asyncio
    async def test_fiscal_limit_guard_rejects_amount_minor_mismatch_and_bool(
        self,
    ) -> None:
        redis = fakeredis.aioredis.FakeRedis()
        guard = FiscalLimitGuard(redis_client=redis, daily_cap_usd=50_000.0)

        with pytest.raises(ValueError):
            await guard.reserve(agent_id="a1", amount_minor=True)  # type: ignore[arg-type]

        with pytest.raises(ValueError, match="conflicting amounts"):
            await guard.reserve(
                agent_id="a1",
                amount_usd=10.0,
                amount_minor=500_000,
            )

    def test_bounding_contracts_b1_b2_b6_reject_bool_thresholds_and_drawdown(
        self,
    ) -> None:
        from src.cage_finance.safety.bounding.models import BoundedTradeRequest

        req = BoundedTradeRequest(symbol="AAPL", amount=100.0, side="buy", venue="NYSE")
        assert (
            contract_b1_max_notional(
                req, {"bounding": {"max_single_order_usd": True}}
            ).admitted
            is False
        )
        assert (
            contract_b2_drawdown_breaker(
                req,
                {"drawdown": {"limit": 0.1}},
                current_drawdown=False,  # type: ignore[arg-type]
            ).admitted
            is False
        )
        assert (
            contract_b6_hitl_high_impact(
                req, {"consensus": {"threshold_usd": True}}
            ).admitted
            is False
        )

    def test_approval_covers_trade_rejects_boolean_approved_amount(self) -> None:
        base = {
            "symbol": "AAPL",
            "currency": "USD",
            "trader_id": "t1",
            "trader_role": "trader",
            "side": "buy",
        }
        assert (
            _approval_covers_trade(
                {**base, "amount": True},
                {**base, "amount": 1.0},
            )
            is False
        )
        assert (
            _approval_covers_trade(
                {**base, "amount": 100.0},
                {**base, "amount": True},
            )
            is False
        )
