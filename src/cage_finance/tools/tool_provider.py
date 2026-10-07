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

import asyncio
import hashlib
import json
import logging
import time
import uuid
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from src.gateway.governance.governor.governor import SymbolicGovernor

from src.cage_finance.actuators.broker_actuator import BrokerActuator
from src.cage_finance.models.trade_order import TradeOrder
from src.cage_finance.tools.market_service import get_market_data
from src.cage_finance.tools.trade_inputs import ServerTradeInputs
from src.gateway.governance.contracts import DomainToolProvider
from src.gateway.governance.execution_actuator import (
    dispatch_actuation,
    get_actuator_registry,
)
from src.gateway.governance.seams.actuation import ExecutionClearance
from src.gateway.server.governance_middleware import (
    enforce_approved_governance,
    enforce_governance,
)

logger = logging.getLogger(__name__)

# ── Module-level actuator registration ──
# Register the BrokerActuator on module import so it's available
# for all execute_trade_action calls.
_broker_actuator = BrokerActuator()
get_actuator_registry().register(_broker_actuator, claims={"execute_trade"})


#: Params an approval binds exactly; the amount may only shrink (see _approval_covers_trade).
#: ``side`` is bound so an approved buy can never be re-hydrated as a sell.
_APPROVAL_BOUND_FIELDS = ("symbol", "currency", "trader_id", "trader_role", "side")

TradeSide = Literal["buy", "sell"]


def _approval_covers_trade(approved: dict, requested: dict) -> bool:
    """True iff an approval of ``approved`` authorises executing ``requested``.

    Same instrument, currency, trader and role, and an amount in
    ``(0, approved amount]``: re-hydration may shrink a trade, never grow or
    redirect it.
    """
    if any(approved.get(f) != requested.get(f) for f in _APPROVAL_BOUND_FIELDS):
        return False
    try:
        approved_amount = float(approved["amount"])
        requested_amount = float(requested["amount"])
    except (KeyError, TypeError, ValueError):
        return False
    return 0.0 < requested_amount <= approved_amount


async def execute_trade_action(
    symbol: str,
    amount: float,
    currency: str,
    confidence: float = 0.0,
    transaction_id: str | None = None,
    trader_id: str = "agent_001",
    trader_role: str = "junior",
    dry_run: bool = False,
    deferred_id: str | None = None,
    side: TradeSide = "buy",
    *,
    governor: "SymbolicGovernor",
    inputs: ServerTradeInputs,
) -> str:
    """Execute a financial trade under strict governance.

    This is the single committing run for a trade: ``/governance/validate-action``
    only routes, and never reserves budget or mints a seal.

    Gap 2 fix (No-Direct-Bind): governance returns a routing seal. This
    function verifies the seal before executing the trade, ensuring that
    execution cannot proceed by ignoring the governance response.
    Satisfies: NoDirectBind == (phase = "EXECUTED") => (resolvedAllow = TRUE)

    Args:
        symbol: Ticker symbol (e.g. "AAPL").
        amount: Trade quantity (positive float).
        currency: ISO 4217 currency code (e.g. "USD").
        confidence: Model confidence score [0.0, 1.0].  Callers MUST supply a
            real value — the governance pipeline enforces a minimum threshold
            (US_FED: 0.95).  Omitting this parameter leaves the default 0.0
            which will always fail the confidence gate.
        transaction_id: Optional idempotency key; auto-generated if absent.
        trader_id: Identifier of the requesting agent or user.
        trader_role: RBAC role used for fiscal-limit enforcement.
        dry_run: When True, governance checks run but no broker call is made.
        deferred_id: The ``deferred_id`` a REQUIRE_APPROVAL verdict returned,
            once operators have approved it. With it, the gateway consumes
            that approval exactly once and re-validates the fresh params under
            the POST_HITL profile; without it, the trade is governed in full.
        side: Order side, ``"buy"`` (default) or ``"sell"``. A sell is held
            to the regional FIN-1 sell-fraction limit (UCA-13) against
            ``portfolio_total``, the current NAV the gateway reads from its NAV
            source; the caller cannot supply that value. When the NAV is
            unavailable the sell is refused.
        governor: The assembled governor that seals the trade and settles its
            reservations once the broker has answered.
        inputs: The gateway's sources for the STPA inputs ``latency_ms``
            (UCA-2 / FIN-2: measured age of the symbol's latest quote),
            ``drawdown`` (UCA-5: daily NAV drawdown, percent) and, for a sell,
            ``portfolio_total`` (UCA-13 / FIN-1: current NAV). A caller can
            never supply these values. A source that is unavailable leaves
            its input unset, and the governor refuses the trade.
    """
    from src.gateway.governance.routing_seal import (
        SymbolicGovernorViolation,
        verify_and_consume_seal,
    )

    logger.info(
        "Tool Call: execute_trade(%s, %s, side=%s, confidence=%s, deferred_id=%s)",
        symbol,
        amount,
        side,
        confidence,
        deferred_id,
    )
    if side not in ("buy", "sell"):
        return f"BLOCKED: invalid trade side {side!r}; expected 'buy' or 'sell'."
    if not transaction_id:
        transaction_id = str(uuid.uuid4())

    params: dict[str, Any] = {
        "symbol": symbol,
        "amount": amount,
        "currency": currency,
        "confidence": confidence,
        "transaction_id": transaction_id,
        "trader_id": trader_id,
        "trader_role": trader_role,
        "dry_run": dry_run,
        "side": side,
    }
    # STPA inputs measured server-side for every committing run; a missing
    # one is refused by UCA-2 / UCA-5 / UCA-13 inside the governor, which
    # records the refusal, rather than by this tool.
    params.update(await inputs.resolve(symbol, side=side))

    # Step 1: Enforce governance (commit + seal) and obtain the seal
    try:
        if deferred_id:
            governance_result = await enforce_approved_governance(
                governor,
                "execute_trade",
                params,
                deferred_id=deferred_id,
                approval_covers=_approval_covers_trade,
            )
        else:
            governance_result = await enforce_governance(
                governor, "execute_trade", params
            )
    except PermissionError as exc:
        return f"BLOCKED: {exc}"

    # CRITICAL: Fail-closed seal validation at entry — reject unsealed execution attempts
    if (
        not governance_result
        or not isinstance(governance_result, str)
        or not governance_result.strip()
    ):
        raise SymbolicGovernorViolation(
            "CRITICAL: execute_trade_action invoked without mandatory routing seal.",
            action="execute_trade",
        )

    seal = governance_result

    # Every exit from here on settles the seal's phase-2 commits exactly once
    # (ADR-009): confirmed only if the broker accepted the trade, released on
    # every other path (blocked receipt, invalid seal, dry run, rejection,
    # actuation error).
    executed = False
    try:
        # Step 3: NARROW Receipt Validation (CAGE-SEC-004 fix)
        # A narrowed committing run (SymbolicGovernor._sealed_narrow) seals the
        # clamped params and issues a single-use receipt naming them.
        action_params = params  # Default: use original params

        from src.gateway.governance.narrow_receipt import narrow_receipt_key
        from src.gateway.infrastructure.redis_client import redis_client

        receipt_key = narrow_receipt_key(seal)

        # Attempt to fetch NARROW receipt (fail-silent if not present)
        if redis_client is not None:
            try:
                receipt_data = await redis_client.get(receipt_key)
                if receipt_data:
                    # Delete receipt immediately (one-time use — fetch-and-burn pattern)
                    await redis_client.delete(receipt_key)

                    receipt_payload = json.loads(receipt_data)
                    narrowed_params = receipt_payload.get("narrowed_params", {})
                    receipt_signature = receipt_payload.get("original_signature", "")

                    # Verify original signature matches (prevents receipt forgery)
                    if receipt_signature != seal:
                        logger.error(
                            "🚫 execute_trade: NARROW receipt signature mismatch. "
                            "Receipt sig=%s, Seal=%s",
                            receipt_signature[:16],
                            seal[:16],
                        )
                        return "BLOCKED: Narrowing receipt signature mismatch — possible forgery attempt"

                    # Use narrowed params for trade execution
                    action_params = narrowed_params
                    logger.info(
                        "📐 execute_trade: NARROW receipt validated and consumed. "
                        "Using narrowed params: %s",
                        {
                            k: narrowed_params.get(k)
                            for k in ["symbol", "amount", "confidence"]
                        },
                    )
            except json.JSONDecodeError as exc:
                logger.error(
                    "🚫 execute_trade: NARROW receipt payload invalid JSON: %s",
                    exc,
                )
                return "BLOCKED: Narrowing receipt payload corrupted"
            except Exception as exc:
                # Only log errors, don't block — receipt may legitimately not exist
                logger.debug(
                    "execute_trade: NARROW receipt lookup failed (may be ALLOW verdict): %s",
                    exc,
                )

        # Step 4: Seal verification and consumption (Gap 2 fix / CAGE-SEC-008)
        # verify_and_consume_seal() verifies the seal, then atomically consumes its
        # single-use nonce in Redis (POAM-2026-089: verify -> burn -> execute).
        # Phase 3.2: Verify seal against the params that will actually be executed (narrowed or original)
        try:
            await verify_and_consume_seal(seal, "execute_trade", action_params)
        except SymbolicGovernorViolation as exc:
            logger.error(
                "🔒 execute_trade_action: routing seal verification FAILED — "
                "blocking execution (No-Direct-Bind invariant). Reason: %s",
                exc.reason,
            )
            return "BLOCKED: routing seal invalid, expired, or already consumed — governance authority unresolved."

        if dry_run:
            return "DRY_RUN: APPROVED by OPA, Safety, and Consensus."

        # Step 5: Construct ExecutionClearance (ADR-008 Phase 2 + v3.0 Routing)
        # Build the clearance structure required by the ActuatorRegistry
        clearance = ExecutionClearance(
            thread_id=str(action_params.get("transaction_id", str(uuid.uuid4()))),
            decision="ALLOW",
            decision_path="DIRECT",
            action="execute_trade",
            target=str(action_params.get("symbol", "")),
            operator_urn=str(action_params.get("trader_id", "agent_001")),
            issued_at=int(time.time()),
            issued_at_provenance="CONSTRUCTION_TIME",
            correlation_id=str(action_params.get("transaction_id", str(uuid.uuid4()))),
            correlation_id_source="THREAD_DERIVED",
            governance_decision_digest=seal,
            opa_input_digest=hashlib.sha256(
                json.dumps(action_params, sort_keys=True).encode()
            ).hexdigest(),
            nonce=str(uuid.uuid4()).replace("-", "")[:32],
            params=action_params,
            executor_id="cage_finance_broker",
            target_route="local://default",
            consequence_ceiling="HIGH_FINANCIAL",
            approvals=[],  # Populated by dual-control in future phases
            required_quorum=0,  # No quorum required for single-agent trades
            routing_seal=seal,
        )

        # Step 6: Dispatch through ActuatorRegistry (ADR-008 Phase 1)
        actuator = get_actuator_registry().get_actuator("execute_trade")
        if actuator is None:
            raise SymbolicGovernorViolation(
                "CRITICAL: No actuator registered for execute_trade.",
                action="execute_trade",
            )

        # The kernel dispatcher records the receipt exactly once and turns an
        # actuator exception into an UNKNOWN receipt. Anything not provably
        # REJECTED confirms the reservations rather than releasing headroom.
        receipt = await dispatch_actuation(actuator, clearance)
        executed = receipt.may_have_executed

        if not receipt.accepted:
            findings_str = "; ".join(
                f"{f.get('code', 'UNKNOWN')}: {f.get('detail', '')}"
                for f in receipt.findings
            )
            if executed:
                raise SymbolicGovernorViolation(
                    f"Actuation outcome indeterminate (reservations confirmed "
                    f"pending reconciliation): {findings_str}",
                    action="execute_trade",
                )
            raise SymbolicGovernorViolation(
                f"Actuation rejected: {findings_str}", action="execute_trade"
            )

        return f"EXECUTED: {action_params.get('symbol')} x {action_params.get('amount')} (Receipt ID: {receipt.receipt_id})"
    finally:
        await _settle(governor, seal, executed=executed)


async def _settle(governor: "SymbolicGovernor", seal: str, *, executed: bool) -> None:
    """Confirm or release the seal's reservations; failures need reconciliation."""
    failures = await governor.settle(seal, executed=executed)
    for violation in failures:
        logger.critical(
            "execute_trade: settlement (executed=%s) failed: %s",
            executed,
            violation.message,
        )


class FinancialToolProvider(DomainToolProvider):
    def __init__(self, inputs: ServerTradeInputs) -> None:
        self._inputs = inputs

    def register_tools(self, server: "FastMCP", governor: "SymbolicGovernor") -> None:
        # The MCP schema must expose only the agent-facing parameters, so the
        # governor and the STPA input sources are bound here rather than in
        # the signature.
        inputs = self._inputs

        @server.tool(
            name="execute_trade_action", description=execute_trade_action.__doc__
        )
        async def _execute_trade_tool(
            symbol: str,
            amount: float,
            currency: str,
            confidence: float = 0.0,
            transaction_id: str | None = None,
            trader_id: str = "agent_001",
            trader_role: str = "junior",
            dry_run: bool = False,
            deferred_id: str | None = None,
            side: TradeSide = "buy",
        ) -> str:
            return await execute_trade_action(
                symbol,
                amount,
                currency,
                confidence,
                transaction_id,
                trader_id,
                trader_role,
                dry_run,
                deferred_id,
                side,
                governor=governor,
                inputs=inputs,
            )

        @server.tool()
        async def check_market_status(symbol: str) -> str:
            """Check current status of a market symbol."""
            return await asyncio.to_thread(get_market_data, symbol)

        @server.tool()
        async def get_market_sentiment(symbol: str) -> str:
            """Retrieve current market sentiment for a symbol."""
            return await asyncio.to_thread(get_market_data, symbol)
