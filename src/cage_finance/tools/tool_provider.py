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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

from src.cage_finance.actuators.broker_actuator import BrokerActuator
from src.cage_finance.models.trade_order import TradeOrder
from src.cage_finance.tools.market_service import get_market_data
from src.gateway.governance.contracts import DomainToolProvider
from src.gateway.governance.execution_actuator import get_actuator_registry
from src.gateway.governance.seams.actuation import ExecutionClearance
from src.gateway.governance.singletons import symbolic_governor
from src.gateway.server.governance_middleware import enforce_governance

logger = logging.getLogger(__name__)

# ── Module-level actuator registration ──
# Register the BrokerActuator on module import so it's available
# for all execute_trade_action calls.
_broker_actuator = BrokerActuator()
get_actuator_registry().register(_broker_actuator, claims={"execute_trade"})


async def execute_trade_action(
    symbol: str,
    amount: float,
    currency: str,
    confidence: float = 0.0,
    transaction_id: str | None = None,
    trader_id: str = "agent_001",
    trader_role: str = "junior",
    dry_run: bool = False,
) -> str:
    """Execute a financial trade under strict governance.

    Gap 2 fix (No-Direct-Bind): ``enforce_governance()`` now returns a routing
    seal.  This function verifies the seal before executing the trade, ensuring
    that execution cannot proceed by ignoring the governance response.
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
    """
    from src.gateway.governance.routing_seal import (
        SymbolicGovernorViolation,
        verify_and_consume_seal,
    )

    logger.info(
        "Tool Call: execute_trade(%s, %s, confidence=%s)",
        symbol,
        amount,
        confidence,
    )
    if not transaction_id:
        transaction_id = str(uuid.uuid4())

    params = {
        "symbol": symbol,
        "amount": amount,
        "currency": currency,
        "confidence": confidence,
        "transaction_id": transaction_id,
        "trader_id": trader_id,
        "trader_role": trader_role,
        "dry_run": dry_run,
    }

    # Step 1: Enforce governance and obtain seal
    try:
        governance_result = await enforce_governance("execute_trade", params)
    except PermissionError as exc:
        return f"BLOCKED: {exc}"

    # CRITICAL: Fail-closed seal validation at entry — reject unsealed execution attempts
    if not governance_result or not isinstance(governance_result, str) or not governance_result.strip():
        raise SymbolicGovernorViolation(
            "CRITICAL: execute_trade_action invoked without mandatory routing seal.",
            action="execute_trade"
        )
    
    seal = governance_result

    # Step 2: ConsequenceGateway evaluation (ADR-008 Phase 2)
    # Check if governance_result contains a consequence_token (from FRIA tier)
    # For now, consequence_token would be passed separately if present
    # This is a placeholder for future integration
    
    # Step 3: NARROW Receipt Validation (CAGE-SEC-004 fix)
    # Check for NARROW verdict receipt using seal prefix before seal verification
    action_params = params  # Default: use original params

    from src.gateway.infrastructure.redis_client import redis_client

    # Generate receipt key from seal (first 32 hex chars = 128 bits)
    seal_prefix = seal[:32] if len(seal) >= 32 else seal
    receipt_key = f"narrow:receipt:{seal_prefix}"

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
    # verify_and_consume_seal() burns the single-use nonce in Redis, preventing replay attacks.
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

    # Step 5: Construct ExecutionClearance (ADR-008 Phase 2)
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
        opa_input_digest=hashlib.sha256(json.dumps(action_params, sort_keys=True).encode()).hexdigest(),
        nonce=str(uuid.uuid4()).replace("-", "")[:32],
        params=action_params,
        approvals=[],  # Populated by dual-control in future phases
        required_quorum=0,  # No quorum required for single-agent trades
    )

    # Step 6: Dispatch through ActuatorRegistry (ADR-008 Phase 1)
    actuator = get_actuator_registry().get_actuator("execute_trade")
    if actuator is None:
        raise SymbolicGovernorViolation(
            "CRITICAL: No actuator registered for execute_trade.",
            action="execute_trade"
        )
    
    try:
        receipt = await actuator.actuate(clearance)
        
        if not receipt.accepted:
            # Actuation rejected — rollback state if possible
            if hasattr(symbolic_governor.safety_filter, "rollback_state"):
                raw_amt = action_params.get("amount")
                rollback_amt = (
                    float(raw_amt)
                    if isinstance(raw_amt, (int, float, str))
                    else float(amount)
                )
                await symbolic_governor.safety_filter.rollback_state(rollback_amt)  # type: ignore[misc, func-returns-value]
            
            # Format findings for error message
            findings_str = "; ".join(
                f"{f.get('code', 'UNKNOWN')}: {f.get('detail', '')}"
                for f in receipt.findings
            )
            raise SymbolicGovernorViolation(
                f"Actuation rejected: {findings_str}",
                action="execute_trade"
            )
        
        # Success — return formatted result
        return f"EXECUTED: {action_params.get('symbol')} x {action_params.get('amount')} (Receipt ID: {receipt.receipt_id})"
        
    except SymbolicGovernorViolation:
        raise
    except Exception as exc:
        logger.error("Actuation error: %s", exc)
        if hasattr(symbolic_governor.safety_filter, "rollback_state"):
            raw_amt = action_params.get("amount")
            rollback_amt = (
                float(raw_amt)
                if isinstance(raw_amt, (int, float, str))
                else float(amount)
            )
            await symbolic_governor.safety_filter.rollback_state(rollback_amt)  # type: ignore[misc, func-returns-value]
        return f"ERROR: {exc}"


class FinancialToolProvider(DomainToolProvider):
    def register_tools(self, server: "FastMCP") -> None:
        # Register execute_trade_action as MCP tool
        server.tool()(execute_trade_action)

        @server.tool()
        async def check_market_status(symbol: str) -> str:
            """Check current status of a market symbol."""
            return await asyncio.to_thread(get_market_data, symbol)

        @server.tool()
        async def get_market_sentiment(symbol: str) -> str:
            """Retrieve current market sentiment for a symbol."""
            return await asyncio.to_thread(get_market_data, symbol)
