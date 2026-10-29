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
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from mcp.types import ToolAnnotations

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from src.gateway.governance.governor.governor import SymbolicGovernor

from src.cage_finance.actuators.broker_actuator import BrokerActuator
from src.cage_finance.models.trade_order import TradeOrder, is_valid_transaction_id
from src.cage_finance.tools.market_service import get_market_data
from src.gateway.governance.contracts import DomainToolProvider
from src.gateway.governance.execution_actuator import (
    dispatch_actuation,
    get_actuator_registry,
)
from src.gateway.governance.execution_idempotency import (
    SHARED_CALLER,
    Claim,
    Duplicate,
    ExecutionLedgerUnavailable,
    ExecutionStatus,
    UnsettledDuplicate,
)
from src.gateway.governance.governor.server_inputs import bind_server_inputs
from src.gateway.governance.seams.actuation import ExecutionClearance
from src.gateway.server.governance_middleware import (
    ActionDeferred,
    enforce_approved_governance,
    enforce_governance,
    record_refusal,
)

logger = logging.getLogger(__name__)

# ── Module-level actuator registration ──
# Register the BrokerActuator on module import so it's available
# for all execute_trade_action calls.
_broker_actuator = BrokerActuator()
get_actuator_registry().register(_broker_actuator, claims={"execute_trade"})


#: Params an approval binds exactly; the amount may only shrink (see _approval_covers_trade).
#: ``side`` is bound so an approved buy can never be re-hydrated as a sell.
#: ``trader_id`` / ``trader_role`` are the server-bound values for the verified
#: caller (``TradeInputResolver``), so an approval redeems only for the
#: identity it was granted to.
_APPROVAL_BOUND_FIELDS = ("symbol", "currency", "trader_id", "trader_role", "side")

TradeSide = Literal["buy", "sell"]

#: MCP hints for tools that only read; GatewayMCPClient may resend them.
_READ_ONLY_TOOL = ToolAnnotations(readOnlyHint=True, idempotentHint=True)
#: A trade is an irreversible external commitment, but its mandatory
#: transaction_id makes a resend with the same key a replay of the first outcome.
_TRADE_TOOL = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=True
)


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
    dry_run: bool = False,
    deferred_id: str | None = None,
    side: TradeSide = "buy",
    *,
    governor: "SymbolicGovernor",
) -> str:
    """Execute a financial trade under strict governance.

    This is the single committing run for a trade: ``/governance/validate-action``
    only routes, and never reserves budget or mints a seal.

    Gap 2 fix (No-Direct-Bind): governance returns a routing seal. This
    function verifies the seal before executing the trade, ensuring that
    execution cannot proceed by ignoring the governance response.
    Satisfies: NoDirectBind == (phase = "EXECUTED") => (resolvedAllow = TRUE)

    At most once per ``transaction_id``: the key is claimed in the governor's
    execution ledger before governance runs. A resubmitted key is neither
    governed nor actuated again: it gets back the first attempt's reply, or
    ``UnsettledDuplicate`` is raised while that attempt is still running or its
    actuation outcome is unknown. Every exit records its outcome, and an
    UNKNOWN actuation keeps the claim pending reconciliation. The one
    exception is a resubmission with a ``deferred_id``: an approval may
    re-claim a key whose earlier attempt was BLOCKED (deferred or refused, so
    nothing ran), and the gateway verifies and spends it before anything
    runs. A dry run never actuates, so it claims nothing.

    Args:
        symbol: Ticker symbol (e.g. "AAPL").
        amount: Trade quantity (positive float).
        currency: ISO 4217 currency code (e.g. "USD").
        confidence: Model confidence score [0.0, 1.0].  Callers MUST supply a
            real value — the governance pipeline enforces a minimum threshold
            (US_FED: 0.95).  Omitting this parameter leaves the default 0.0
            which will always fail the confidence gate.
        transaction_id: Required idempotency key for this trade, a UUIDv4 or
            UUIDv5; the broker receives it as ``client_order_id``. A missing or
            invalid one is refused.
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
            reservations once the broker has answered. Its ``execute_trade``
            server-input resolver (the finance plugin's
            :class:`~src.cage_finance.tools.trade_inputs.TradeInputResolver`)
            supplies ``latency_ms`` (UCA-2 / FIN-2), ``drawdown`` (UCA-5) and,
            for a sell, ``portfolio_total`` (UCA-13 / FIN-1); a caller can
            never supply them. An unavailable source leaves its input unset,
            and the governor refuses the trade. The same resolver binds
            ``trader_role`` (the RBAC role that sets the trade's OPA limits)
            and ``trader_id`` from the caller's verified workload identity,
            which is why neither is a parameter here (GHSA-w39v-5v7h-fxg9).
    """
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
        return (
            "BLOCKED: transaction_id is required (a UUIDv4 or UUIDv5 idempotency key)."
        )
    if not is_valid_transaction_id(transaction_id):
        return (
            f"BLOCKED: invalid transaction_id {str(transaction_id)[:64]!r}; "
            "expected a UUIDv4 or UUIDv5."
        )
    transaction_id = transaction_id.lower()

    params: dict[str, Any] = {
        "symbol": symbol,
        "amount": amount,
        "currency": currency,
        "confidence": confidence,
        "transaction_id": transaction_id,
        "dry_run": dry_run,
        "side": side,
    }
    ledger = governor.components.execution_ledger
    claim: Claim | None = None
    if not dry_run:
        # Keys are namespaced by action only: this tool is also reached through
        # the gateway's HTTP /tools/execute dispatch, which passes no request
        # context, and a resubmission must collide whichever path it takes.
        # Both paths admit only trusted workload identities. An approval is
        # new authority, so it may take over a key whose attempt was BLOCKED;
        # a key whose trade may have executed is never claimed again.
        try:
            claimed = await ledger.claim(
                "execute_trade",
                SHARED_CALLER,
                transaction_id,
                reclaim_blocked=bool(deferred_id),
            )
        except ExecutionLedgerUnavailable as exc:
            reason = (
                "execution ledger unavailable, at-most-once execution cannot be "
                f"guaranteed: {exc}"
            )
            logger.error("execute_trade %s refused: %s", transaction_id, reason)
            await record_refusal(
                "execute_trade", reason, oscal_control_ref="AC-3", params=params
            )
            return f"BLOCKED: {reason}"
        if isinstance(claimed, Duplicate):
            return await _refuse_duplicate(claimed, transaction_id, params)
        claim = claimed

    attempt = _TradeAttempt()
    try:
        outcome = await _govern_and_actuate(
            params,
            deferred_id=deferred_id,
            dry_run=dry_run,
            governor=governor,
            attempt=attempt,
        )
    except BaseException as exc:
        if claim is not None:
            await ledger.record_outcome(
                claim,
                attempt.status,
                f"{attempt.status.value}: {str(exc) or type(exc).__name__}",
            )
        raise
    if claim is not None:
        await ledger.record_outcome(claim, attempt.status, outcome)
    return outcome


#: Ledger statuses whose recorded reply settles a resubmission.
_SETTLED = frozenset({ExecutionStatus.EXECUTED, ExecutionStatus.BLOCKED})


@dataclass
class _TradeAttempt:
    """What one attempt did at the broker, as the execution ledger records it."""

    status: ExecutionStatus = ExecutionStatus.BLOCKED


async def _refuse_duplicate(
    duplicate: Duplicate, transaction_id: str, params: dict[str, Any]
) -> str:
    """Answer a resubmitted ``transaction_id`` without governing it again.

    A first attempt that finished (EXECUTED or BLOCKED) is answered with its
    own reply. One that may still act, or may have acted (IN_FLIGHT,
    UNKNOWN), raises ``UnsettledDuplicate``, as an UNKNOWN actuation raises,
    so that no caller reads the reply as settled.
    """
    reason = (
        f"duplicate submission of transaction_id {transaction_id} "
        f"(first attempt {duplicate.status.value})"
    )
    logger.warning("execute_trade refused: %s", reason)
    await record_refusal(
        "execute_trade", reason, oscal_control_ref="AC-3", params=params
    )
    if duplicate.outcome is not None and duplicate.status in _SETTLED:
        return duplicate.outcome
    state = {
        ExecutionStatus.IN_FLIGHT: "has not finished",
        ExecutionStatus.UNKNOWN: "has an unknown outcome, pending reconciliation",
    }.get(duplicate.status, "left no recorded reply")
    first = f" First attempt: {duplicate.outcome}" if duplicate.outcome else ""
    raise UnsettledDuplicate(
        f"{duplicate.status.value}: transaction_id {transaction_id} was already "
        f"submitted and its first attempt {state}; it is not executed again.{first}"
    )


async def _govern_and_actuate(
    params: dict[str, Any],
    *,
    deferred_id: str | None,
    dry_run: bool,
    governor: "SymbolicGovernor",
    attempt: _TradeAttempt,
) -> str:
    """Govern, seal and actuate one trade; ``attempt.status`` tracks the broker."""
    from src.gateway.governance.routing_seal import (
        SymbolicGovernorViolation,
        seal_digest,
        verify_and_consume_seal,
    )

    # Server-side inputs (the STPA measurements and the trader's role and id)
    # are bound by the kernel, exactly as for previews; the seal names these
    # bound params. A missing one is refused inside the governor (UCA-2 /
    # UCA-5 / UCA-13, or the trade policy for a missing role), which records
    # the refusal.
    params = await bind_server_inputs(
        governor.components.server_inputs, "execute_trade", params
    )

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
    except ActionDeferred as exc:
        # Nothing sealed, committed or refused. After an approval, the same
        # approval redeems once the deferral clears (the warrant is eligible
        # again); otherwise the request is parked as exc.deferred_id.
        return f"DEFERRED: {exc}"
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
            governance_decision_digest=seal_digest(seal),
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
        attempt.status = ExecutionStatus.UNKNOWN  # the broker may act from here on
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
            attempt.status = ExecutionStatus.BLOCKED
            raise SymbolicGovernorViolation(
                f"Actuation rejected: {findings_str}", action="execute_trade"
            )

        attempt.status = ExecutionStatus.EXECUTED
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
    def register_tools(self, server: "FastMCP", governor: "SymbolicGovernor") -> None:
        # The MCP schema must expose only the agent-facing parameters, so the
        # governor is bound here rather than in the signature. Who is trading
        # (trader_role / trader_id) is not agent-facing: the gateway binds it
        # from the caller's verified workload identity (GHSA-w39v-5v7h-fxg9).

        @server.tool(
            name="execute_trade_action",
            description=execute_trade_action.__doc__,
            annotations=_TRADE_TOOL,
        )
        async def _execute_trade_tool(
            symbol: str,
            amount: float,
            currency: str,
            confidence: float = 0.0,
            transaction_id: str | None = None,
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
                dry_run,
                deferred_id,
                side,
                governor=governor,
            )

        @server.tool(annotations=_READ_ONLY_TOOL)
        async def check_market_status(symbol: str) -> str:
            """Check current status of a market symbol."""
            return await asyncio.to_thread(get_market_data, symbol)

        @server.tool(annotations=_READ_ONLY_TOOL)
        async def get_market_sentiment(symbol: str) -> str:
            """Retrieve current market sentiment for a symbol."""
            return await asyncio.to_thread(get_market_data, symbol)
