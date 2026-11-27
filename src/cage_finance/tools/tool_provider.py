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
from typing import TYPE_CHECKING, Any, Literal, NoReturn

from mcp.types import CallToolResult, ToolAnnotations

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from src.gateway.governance.governor.governor import SymbolicGovernor

from src.cage_finance.actuators.broker_actuator import BrokerActuator
from src.cage_finance.tools.market_service import get_market_data
from src.gateway.governance import execution_actuator as _exec_actuator
from src.gateway.governance import execution_idempotency as _idempotency
from src.gateway.governance.commit_outcome import (
    CommitOutcome,
    CommitStatus,
    commit_tool_result,
)
from src.gateway.governance.contracts import DomainToolProvider
from src.gateway.governance.execution_actuator import get_actuator_registry
from src.gateway.governance.execution_idempotency import (
    ExecutionStatus,
    UnsettledDuplicate,
    actuation_attempt_scope,
    current_actuation_attempt,
    outcome_after_dispatch,
)
from src.gateway.governance.routing_seal import SymbolicGovernorViolation
from src.gateway.governance.seams.actuation import (
    ActuationIndeterminateError,
    ActuationRejectedError,
    ExecutionClearance,
)
from src.gateway.server.governance_middleware import (
    ActionDeferred,
    ApprovalRedemptionRefused,
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
#: idempotency_key makes a resend with the same key a replay of the first outcome.
_TRADE_TOOL = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=True
)


def _approval_covers_trade(approved: dict, requested: dict) -> bool:
    """True iff an approval of ``approved`` authorises executing ``requested``.

    Same instrument, currency, trader and role, and an amount in
    ``(0, approved amount]``: re-hydration may shrink a trade, never grow or
    redirect it.
    """
    return _exec_actuator.approval_covers_bounded(
        approved,
        requested,
        _APPROVAL_BOUND_FIELDS,
        "amount",
    )


async def execute_trade_action(
    symbol: str,
    amount: float,
    currency: str,
    confidence: float = 0.0,
    idempotency_key: str | None = None,
    dry_run: bool = False,
    deferred_id: str | None = None,
    side: TradeSide = "buy",
    *,
    governor: "SymbolicGovernor",
) -> CommitOutcome:
    """Execute a financial trade under strict governance.

    This is the single committing run for a trade: ``/governance/validate-action``
    only routes, and never reserves budget or mints a seal.

    Gap 2 fix (No-Direct-Bind): governance returns a sealed action (the
    routing seal and the evaluated params it commits to). This function
    verifies the seal against those params and actuates exactly them,
    ensuring that execution cannot proceed by ignoring the governance
    response.
    Satisfies: NoDirectBind == (phase = "EXECUTED") => (resolvedAllow = TRUE)

    At most once per ``idempotency_key``: the key is claimed in the governor's
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
        amount: Trade notional in ``currency`` (positive float), not a share
            count.
        currency: ISO 4217 currency code (e.g. "USD").
        confidence: Model confidence score [0.0, 1.0].  Callers MUST supply a
            real value — the governance pipeline enforces a minimum threshold
            (US_FED: 0.95).  Omitting this parameter leaves the default 0.0
            which will always fail the confidence gate.
        idempotency_key: Required idempotency key for this trade, a UUIDv4 or
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

    Returns:
        A ``CommitOutcome``: its ``status`` (EXECUTED, DRY_RUN, REFUSED or
        DEFERRED) is the result and ``message`` is prose only. A refused
        ``deferred_id`` names why in ``redemption_refusal``.
    """
    logger.info(
        "Tool Call: execute_trade(%s, %s, side=%s, confidence=%s, deferred_id=%s)",
        symbol,
        amount,
        side,
        confidence,
        deferred_id,
    )
    raw_params: dict[str, Any] = {
        "symbol": symbol,
        "amount": amount,
        "currency": currency,
        "confidence": confidence,
        "idempotency_key": str(idempotency_key or ""),
        "dry_run": dry_run,
        "side": str(side),
    }
    if side not in ("buy", "sell"):
        reason = f"invalid trade side {side!r}; expected 'buy' or 'sell'."
        await record_refusal(
            "execute_trade", reason, oscal_control_ref="AC-3", params=raw_params
        )
        return _refused(reason)
    # Kernel-owned at-most-once claim lifecycle (POAM-2026-254) and single
    # attempt record (POAM-2026-252): this tool holds no private ledger calls.
    async with _idempotency.execution_claim_scope(
        governor,
        action="execute_trade",
        idempotency_key=idempotency_key,
        params=raw_params,
        dry_run=dry_run,
        reclaim_blocked=bool(deferred_id),
    ) as scope:
        if scope.invalid_key_reason is not None:
            return _refused(scope.invalid_key_reason)
        if scope.duplicate is not None:
            return CommitOutcome(
                _REPLAYED_STATUS[scope.duplicate.status],
                scope.duplicate.outcome or "",
            )
        normalized_key = scope.idempotency_key
        if not normalized_key:
            return _refused(
                "idempotency_key is required (a UUIDv4 or UUIDv5 idempotency key)."
            )
        params: dict[str, Any] = {
            "symbol": symbol,
            "amount": amount,
            "currency": currency,
            "confidence": confidence,
            "idempotency_key": normalized_key,
            "dry_run": dry_run,
            "side": side,
        }
        outcome = await _govern_and_actuate(
            params,
            deferred_id=deferred_id,
            dry_run=dry_run,
            governor=governor,
        )
        scope.set_outcome_summary(outcome.message)
        return outcome


#: Outcome status reported when replaying a settled ledger duplicate.
_REPLAYED_STATUS: dict[ExecutionStatus, CommitStatus] = {
    ExecutionStatus.EXECUTED: CommitStatus.EXECUTED,
    ExecutionStatus.BLOCKED: CommitStatus.REFUSED,
}


def _refused(reason: str) -> CommitOutcome:
    """A ``REFUSED`` outcome: nothing was executed."""
    return CommitOutcome(CommitStatus.REFUSED, f"BLOCKED: {reason}")


async def _govern_and_actuate(
    params: dict[str, Any],
    *,
    deferred_id: str | None,
    dry_run: bool,
    governor: "SymbolicGovernor",
) -> CommitOutcome:
    """Govern, seal and actuate one trade.

    Runs inside :func:`execute_trade_action`'s attempt scope. Whether the
    trade may have executed is read from the kernel's attempt record, which
    only ``dispatch_actuation()`` writes (POAM-2026-252); this function never
    derives it from the receipt itself.
    """
    # The kernel binds the server-side inputs (the STPA measurements and the
    # trader's role and id) exactly once inside the committing run; the seal
    # names those evaluated params and the run returns them
    # (SealedAction.params). They, never the caller's params, are what is
    # verified and actuated. A missing input is refused inside the governor
    # (UCA-2 / UCA-5 / UCA-13, or the trade policy for a missing role), which
    # records the refusal; an unavailable source blocks with a 503.
    from src.gateway.governance.routing_seal import (
        seal_digest,
        verify_and_consume_seal,
    )

    # Step 1: Enforce governance (commit + seal) and obtain the sealed action
    try:
        if deferred_id:
            governed = await enforce_approved_governance(
                governor,
                "execute_trade",
                params,
                deferred_id=deferred_id,
                approval_covers=_approval_covers_trade,
            )
        else:
            governed = await enforce_governance(governor, "execute_trade", params)
    except ActionDeferred as exc:
        # Nothing sealed, committed or refused. After an approval, the same
        # approval redeems once the deferral clears (the warrant is eligible
        # again); otherwise the request is parked as exc.deferred_id.
        return CommitOutcome(
            CommitStatus.DEFERRED,
            f"DEFERRED: {exc}",
            deferred_id=exc.deferred_id or None,
            approval_retained=exc.approval_retained,
        )
    except ApprovalRedemptionRefused as exc:
        # The named approval is not redeemable: the typed reason travels in
        # the outcome so the caller can tell "not yet approved" from "gone".
        return CommitOutcome(
            CommitStatus.REFUSED,
            f"BLOCKED: {exc}",
            redemption_refusal=exc.refusal,
        )
    except PermissionError as exc:
        return _refused(str(exc))

    # CRITICAL: Fail-closed seal validation at entry — reject unsealed execution attempts
    seal = getattr(governed, "seal", None)
    action_params = getattr(governed, "params", None)
    if (
        not isinstance(seal, str)
        or not seal.strip()
        or not isinstance(action_params, dict)
    ):
        raise SymbolicGovernorViolation(
            "CRITICAL: execute_trade_action invoked without mandatory routing seal.",
            action="execute_trade",
        )

    # Every exit from here on settles the seal's phase-2 commits exactly once
    # (ADR-009), as the kernel's attempt record says: confirmed whenever the
    # trade may have executed (ACCEPTED, UNKNOWN, or mid-dispatch
    # cancellation), and released only while nothing was dispatched or the
    # receipt was a deterministic REJECTED (blocked receipt, invalid seal, dry
    # run, missing actuator, REJECTED receipt).
    try:
        # Step 3: NARROW Receipt Validation (CAGE-SEC-004 fix)
        # A narrowed committing run (SymbolicGovernor._sealed_narrow) seals the
        # re-bound clamped params, returns them as governed.params and issues a
        # single-use receipt naming them. governed.params is what is verified
        # and actuated; the receipt is fetched, burned and must name exactly
        # those params. Whenever the run narrowed the request the receipt is
        # required, so a narrowing is never executed unconfirmed: a missing
        # receipt, another seal's receipt or a receipt naming other params is a
        # recorded refusal, and an unreachable receipt store blocks (503).
        narrowed = _narrowed(params, action_params)
        receipt, receipt_store_error = await _take_narrow_receipt(seal)
        if receipt_store_error is not None and narrowed:
            await _block_receipt_store_outage(action_params, receipt_store_error)
        refusal: str | None = None
        if receipt is _CORRUPT_RECEIPT:
            refusal = "Narrowing receipt payload corrupted"
        elif isinstance(receipt, dict):
            if receipt.get("original_signature", "") != seal:
                refusal = (
                    "Narrowing receipt signature mismatch — possible forgery attempt"
                )
            elif not _same_params(receipt.get("narrowed_params"), action_params):
                refusal = (
                    "Narrowing receipt names params other than the sealed params "
                    "— refusing"
                )
        elif narrowed:
            refusal = "Narrowing receipt missing — the narrowed params are unconfirmed"
        if refusal is not None:
            logger.error("🚫 execute_trade: NARROW receipt refused: %s", refusal)
            await record_refusal(
                "execute_trade",
                refusal,
                oscal_control_ref="AC-3",
                params=action_params,
            )
            return _refused(refusal)
        if isinstance(receipt, dict):
            logger.info(
                "📐 execute_trade: NARROW receipt validated and consumed. "
                "Executing narrowed params: %s",
                {k: action_params.get(k) for k in ["symbol", "amount", "confidence"]},
            )

        # Step 4: Seal verification and consumption (Gap 2 fix / CAGE-SEC-008)
        # verify_and_consume_seal() verifies the seal, then atomically consumes its
        # single-use nonce in Redis (POAM-2026-089: verify -> burn -> execute).
        # The seal is verified against the evaluated params the run sealed and
        # returned (governed.params), the params that are actuated below.
        try:
            await verify_and_consume_seal(seal, "execute_trade", action_params)
        except SymbolicGovernorViolation as exc:
            reason = (
                "routing seal invalid, expired, or already consumed — "
                "governance authority unresolved."
            )
            logger.error(
                "🔒 execute_trade_action: routing seal verification FAILED — "
                "blocking execution (No-Direct-Bind invariant). Reason: %s",
                exc.reason,
            )
            await record_refusal(
                "execute_trade",
                f"{reason} ({exc.reason})",
                oscal_control_ref="AC-3",
                params=action_params,
            )
            return _refused(reason)

        if dry_run:
            return CommitOutcome(
                CommitStatus.DRY_RUN, "DRY_RUN: APPROVED by OPA, Safety, and Consensus."
            )

        # Step 5: Construct ExecutionClearance (ADR-008 Phase 2 + v3.0 Routing)
        clearance = ExecutionClearance(
            thread_id=str(action_params.get("idempotency_key", str(uuid.uuid4()))),
            decision="ALLOW",
            decision_path="DIRECT",
            action="execute_trade",
            target=str(action_params.get("symbol", "")),
            operator_urn=str(action_params.get("trader_id", "agent_001")),
            issued_at=int(time.time()),
            issued_at_provenance="CONSTRUCTION_TIME",
            correlation_id=str(action_params.get("idempotency_key", str(uuid.uuid4()))),
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
            approvals=[],
            required_quorum=0,
            routing_seal=seal,
        )

        # Step 6: Dispatch through ActuatorRegistry (ADR-008 Phase 1).
        actuator = get_actuator_registry().get_actuator("execute_trade")
        if actuator is None:
            raise SymbolicGovernorViolation(
                "CRITICAL: No actuator registered for execute_trade.",
                action="execute_trade",
            )

        # dispatch_actuation() marks the kernel attempt record UNKNOWN before
        # it awaits the broker, so mid-flight cancellation (BaseException) or
        # an indeterminate outcome NEVER rolls back CBF or FiscalLimitGuard
        # reservations; only a provable REJECTED receipt settles it BLOCKED.
        receipt = await _exec_actuator.dispatch_actuation(actuator, clearance)
        status = _attempt_status()
        if status is ExecutionStatus.EXECUTED:
            return CommitOutcome(
                CommitStatus.EXECUTED,
                f"EXECUTED: {action_params.get('symbol')} x {action_params.get('amount')} "
                f"(Receipt ID: {receipt.receipt_id})",
            )
        findings_str = "; ".join(
            f"{f.get('code', 'UNKNOWN')}: {f.get('detail', '')}"
            for f in receipt.findings
        )
        if status is ExecutionStatus.UNKNOWN:
            raise ActuationIndeterminateError(
                f"Actuation outcome indeterminate (reservations confirmed "
                f"pending reconciliation): {findings_str}",
                action="execute_trade",
                findings=receipt.findings,
            )
        raise ActuationRejectedError(
            f"Actuation rejected: {findings_str}",
            action="execute_trade",
            findings=receipt.findings,
        )
    finally:
        attempt_status = _attempt_status()
        fiscal_token = (
            governor.held_receipt(seal, "fiscal")
            if hasattr(governor, "held_receipt")
            else None
        )
        await _settle(
            governor, seal, executed=attempt_status is not ExecutionStatus.BLOCKED
        )
        if attempt_status is ExecutionStatus.UNKNOWN:
            await _record_unknown_fiscal_hold(
                governor,
                idempotency_key=str(action_params.get("idempotency_key") or ""),
                symbol=str(action_params.get("symbol") or ""),
                fiscal_token=fiscal_token,
            )


def _attempt_status() -> ExecutionStatus:
    """The trade's status in the kernel attempt record (POAM-2026-252).

    ``BLOCKED`` outside every scope: ``dispatch_actuation()`` refuses to run
    there, so nothing can have been dispatched.
    """
    attempt = current_actuation_attempt()
    return ExecutionStatus.BLOCKED if attempt is None else attempt.status


#: Sentinel for a NARROW receipt whose payload is not a JSON object.
_CORRUPT_RECEIPT = object()


def _narrowed(requested: dict[str, Any], sealed: dict[str, Any]) -> bool:
    """True iff the run sealed other values for keys the tool requested (a NARROW).

    The tool's params carry no server-owned key, so an ALLOW seals every
    requested key unchanged; a narrower clamps a requested value (e.g. the
    amount). A key the tool did not send cannot make this true, so server
    inputs bound by the kernel never count as a narrowing.
    """
    return any(
        key not in sealed or sealed[key] != value for key, value in requested.items()
    )


def _same_params(receipt_params: Any, sealed: dict[str, Any]) -> bool:
    """Whether a receipt names exactly the sealed params, in the seal's own canonical form.

    Both sides go through :func:`~src.gateway.governance.routing_seal.canonical_action_bytes`
    (RFC 8785 JCS, the recipe of the seal's ``action_hash``), so the comparison
    is byte-deterministic and cannot disagree with the seal. Anything that
    recipe cannot represent is a mismatch.
    """
    from src.gateway.governance.routing_seal import (
        SealCanonicalizationError,
        canonical_action_bytes,
    )

    if not isinstance(receipt_params, dict):
        return False
    try:
        return canonical_action_bytes(
            "execute_trade", receipt_params
        ) == canonical_action_bytes("execute_trade", sealed)
    except SealCanonicalizationError:
        return False


async def _take_narrow_receipt(seal: str) -> tuple[Any, Exception | None]:
    """Fetch and burn the NARROW receipt for ``seal``.

    Returns ``(receipt, store_error)``: the receipt as a dict,
    :data:`_CORRUPT_RECEIPT` for a payload that is not a JSON object, or
    ``None`` when there is none (also when no receipt store is configured);
    ``store_error`` is the exception raised by an unreachable store.
    """
    from src.gateway.governance.narrow_receipt import narrow_receipt_key
    from src.gateway.infrastructure.redis_client import redis_client

    if redis_client is None:
        return None, None
    receipt_key = narrow_receipt_key(seal)
    try:
        receipt_data = await redis_client.get(receipt_key)
        if receipt_data:
            # One-time use: the receipt is burned before it is read.
            await redis_client.delete(receipt_key)
    except Exception as exc:  # the store, not the receipt, failed
        return None, exc
    if not receipt_data:
        return None, None
    try:
        payload = json.loads(receipt_data)
    except (TypeError, ValueError):  # json.JSONDecodeError is a ValueError
        return _CORRUPT_RECEIPT, None
    return (payload if isinstance(payload, dict) else _CORRUPT_RECEIPT), None


async def _block_receipt_store_outage(
    params: dict[str, Any], exc: Exception
) -> NoReturn:
    """Block a narrowed trade whose receipt store is unreachable (503, no refusal).

    An outage is not a policy refusal (POAM-2026-233): the block is chained
    as ``GOVERNANCE_INFRASTRUCTURE_BLOCK`` and nothing executes.
    """
    from src.gateway.governance.contracts import Violation, ViolationKind
    from src.gateway.governance.governor.errors import GovernanceInfrastructureError
    from src.gateway.governance.governor.verdicts import handle_infrastructure_block

    logger.error("execute_trade: NARROW receipt store unreachable: %s", exc)
    await handle_infrastructure_block(
        "execute_trade",
        params,
        [
            Violation(
                tier="narrow_receipt_store",
                code="NARROW_RECEIPT_UNAVAILABLE",
                message=(
                    "NARROW receipt store unreachable; the narrowed params cannot "
                    f"be confirmed: {type(exc).__name__}: {exc}"
                ),
                kind=ViolationKind.INFRASTRUCTURE,
                infra_dependency="narrow_receipt_store",
                infra_error_code="narrow_receipt_store_unavailable",
            )
        ],
        [],
    )
    raise GovernanceInfrastructureError(
        "handle_infrastructure_block returned without raising; blocking execute_trade",
        dependency="narrow_receipt_store",
        failure_code="NARROW_RECEIPT_UNAVAILABLE",
        error_code="narrow_receipt_store_unavailable",
    )  # fail closed


def _fiscal_guard_from(governor: "SymbolicGovernor") -> Any | None:
    """Return the domain ``FiscalLimitGuard`` held by ``governor``, if any."""
    components = getattr(governor, "components", None)
    for tier in getattr(components, "domain_tiers", ()) or ():
        if getattr(tier, "tier_name", None) == "fiscal":
            return getattr(tier, "guard", None)
    return None


async def _record_unknown_fiscal_hold(
    governor: "SymbolicGovernor",
    *,
    idempotency_key: str,
    symbol: str,
    fiscal_token: Any | None,
) -> None:
    """Record a confirmed UNKNOWN fiscal reservation for same-day broker reconciliation."""
    metrics = getattr(getattr(governor, "components", None), "metrics", None)
    if metrics is not None and hasattr(metrics, "unknown_actuation_event"):
        metrics.unknown_actuation_event("recorded")
    if fiscal_token is None or not idempotency_key:
        return
    guard = _fiscal_guard_from(governor)
    if guard is None or not hasattr(guard, "record_unverified_unknown"):
        return
    try:
        await guard.record_unverified_unknown(
            idempotency_key,
            fiscal_token,
            symbol=symbol,
        )
    except Exception as exc:
        logger.critical(
            "execute_trade: failed to record unverified UNKNOWN fiscal hold tx=%s: %s",
            idempotency_key,
            exc,
        )


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
            idempotency_key: str | None = None,
            dry_run: bool = False,
            deferred_id: str | None = None,
            side: TradeSide = "buy",
        ) -> CallToolResult:
            # The typed outcome rides in structuredContent (POAM-2026-245 / 232).
            # An error that escapes once the trade may have executed is
            # answered from the kernel attempt record, whatever its type; the
            # type mapping applies only while nothing may have executed
            # (POAM-2026-252).
            with actuation_attempt_scope():
                try:
                    outcome = await execute_trade_action(
                        symbol,
                        amount,
                        currency,
                        confidence,
                        idempotency_key,
                        dry_run,
                        deferred_id,
                        side,
                        governor=governor,
                    )
                except Exception as exc:
                    after_dispatch = outcome_after_dispatch(
                        str(exc) or type(exc).__name__
                    )
                    if after_dispatch is not None:
                        logger.warning(
                            "Trade error after dispatch answered as %s (%s): %s",
                            after_dispatch.status.value,
                            type(exc).__name__,
                            exc,
                        )
                        outcome = after_dispatch
                    elif isinstance(exc, ActuationIndeterminateError):
                        outcome = CommitOutcome(CommitStatus.INDETERMINATE, str(exc))
                    elif isinstance(exc, UnsettledDuplicate):
                        outcome = CommitOutcome(
                            CommitStatus.UNSETTLED_DUPLICATE, str(exc)
                        )
                    elif isinstance(exc, ActuationRejectedError):
                        outcome = CommitOutcome(CommitStatus.REFUSED, str(exc))
                    else:
                        raise
            return commit_tool_result(outcome)

        @server.tool(annotations=_READ_ONLY_TOOL)
        async def check_market_status(symbol: str) -> str:
            """Check current status of a market symbol."""
            return await asyncio.to_thread(get_market_data, symbol)

        @server.tool(annotations=_READ_ONLY_TOOL)
        async def get_market_sentiment(symbol: str) -> str:
            """Retrieve current market sentiment for a symbol."""
            return await asyncio.to_thread(get_market_data, symbol)
