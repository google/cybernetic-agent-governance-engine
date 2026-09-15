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

"""
BrokerActuator — Finance Domain Execution Actuator (ADR-008 Phase 1 & 2).

Implements the ExecutionActuator protocol for financial trades, bridging the
governance kernel's ExecutionClearance to the domain-specific trade_executor.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

from src.cage_finance.models.trade_order import TradeOrder
from src.cage_finance.tools.trade_executor import execute_trade
from src.gateway.governance.seams.actuation import (
    ActuationReceipt,
    ActuatorCapability,
    ExecutionClearance,
)
from src.gateway.infrastructure.config_manager import config_manager

logger = logging.getLogger(__name__)


class BrokerActuator:
    """
    Finance domain actuator for trade execution.

    Implements ExecutionActuator protocol to receive governance clearances
    and dispatch them to the broker execution layer.

    Capabilities:
        - REPLAY_PROTECTED: Nonce-based replay prevention via routing seal

    Architectural position:
        Layer 2 (Domain Plugin) → Layer 1 (Kernel) boundary enforcement.
        Never imports from Layer 1 governance internals.
    """

    @property
    def actuator_id(self) -> str:
        """Unique identifier for this actuator."""
        return "cage_finance_broker"

    async def health_check(self) -> bool:
        """
        Check if the broker actuator is ready to accept clearances.

        Returns False (fail-closed) when:
        - Broker credentials are missing in non-mock environments
        - Configuration is invalid

        Returns:
            True if actuator is ready, False otherwise.
        """
        try:
            # Check if we're in mock mode (always healthy)
            import os

            use_mock = os.getenv("USE_MOCK_BROKER", "false").lower() in (
                "true",
                "1",
                "yes",
            )
            if use_mock:
                return True

            # Verify broker credentials are configured
            api_key = config_manager.get("BROKER_API_KEY")
            api_secret = config_manager.get("BROKER_API_SECRET")

            return bool(api_key and api_secret)
        except Exception as exc:
            logger.error("BrokerActuator health check failed: %s", exc)
            return False

    def get_capabilities(self) -> set[ActuatorCapability]:
        """Declare actuator capabilities."""
        return {ActuatorCapability.REPLAY_PROTECTED}

    async def actuate(self, clearance: ExecutionClearance) -> ActuationReceipt:
        """
        Execute a trade based on the governance clearance.

        This method:
        1. Validates clearance signature digest and quorum
        2. Constructs TradeOrder from clearance parameters
        3. Invokes execute_trade with routing_seal
        4. Returns ActuationReceipt on success or detailed findings on failure

        Args:
            clearance: Validated ExecutionClearance from governance kernel

        Returns:
            ActuationReceipt with accepted=True on success, or accepted=False
            with structured findings on failure.
        """
        timestamp_utc = datetime.now(tz=timezone.utc).isoformat()
        findings: list[dict] = []

        # ── v3.0 Security Gates ───────────────────────────────────────────

        # Gate 1: Identity validation
        if clearance.executor_id != self.actuator_id:
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    {
                        "code": "EXECUTOR_ID_MISMATCH",
                        "severity": "TERMINAL",
                        "detail": f"Clearance executor_id '{clearance.executor_id}' does not match '{self.actuator_id}'",
                    }
                ],
                retryable=False,
                timestamp_utc=timestamp_utc,
            )

        # Gate 2: Route validation (in-process broker only accepts local routes)
        normalized_target = clearance.target_route.rstrip("/")
        if normalized_target not in ("local://default", "*"):
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=[
                    {
                        "code": "TARGET_ROUTE_MISMATCH",
                        "severity": "TERMINAL",
                        "detail": f"Route '{clearance.target_route}' invalid for in-process broker actuator",
                    }
                ],
                retryable=False,
                timestamp_utc=timestamp_utc,
            )

        # Step 1: Validate clearance pre-conditions
        if clearance.decision != "ALLOW":
            findings.append(
                {
                    "code": "CLEARANCE_NOT_ALLOW",
                    "detail": f"Clearance decision must be ALLOW, got {clearance.decision}",
                }
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=findings,
                retryable=False,
                timestamp_utc=timestamp_utc,
            )

        # Step 2: Validate quorum threshold
        if len(clearance.approvals) < clearance.required_quorum:
            findings.append(
                {
                    "code": "QUORUM_NOT_MET",
                    "detail": f"Required quorum: {clearance.required_quorum}, got {len(clearance.approvals)} approvals",
                }
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=findings,
                retryable=False,
                timestamp_utc=timestamp_utc,
            )

        # Step 3: Validate governance decision digest is present
        if not clearance.governance_decision_digest:
            findings.append(
                {
                    "code": "MISSING_GOVERNANCE_DIGEST",
                    "detail": "governance_decision_digest is required for actuation",
                }
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=findings,
                retryable=False,
                timestamp_utc=timestamp_utc,
            )

        # Step 4: Construct TradeOrder from clearance.params
        try:
            logger.info(
                "BrokerActuator: Constructing TradeOrder from clearance "
                "thread_id=%s action=%s governance_digest=%s",
                clearance.thread_id,
                clearance.action,
                clearance.governance_decision_digest[:16],
            )

            # Construct TradeOrder from clearance.params
            order = TradeOrder(**clearance.params)  # type: ignore[arg-type]

        except Exception as exc:
            logger.error("BrokerActuator: Failed to construct TradeOrder: %s", exc)
            findings.append(
                {
                    "code": "ORDER_CONSTRUCTION_FAILED",
                    "detail": str(exc),
                }
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=findings,
                retryable=False,
                timestamp_utc=timestamp_utc,
            )

        # Step 5: Execute trade with routing seal (governance_decision_digest)
        try:
            result_msg = await execute_trade(
                order,
                routing_seal=clearance.governance_decision_digest,
            )

            # Extract order ID from result message
            receipt_id = clearance.nonce  # Use clearance nonce as receipt ID
            logger.info(
                "BrokerActuator: Trade executed successfully: %s",
                result_msg,
            )

            # Compute envelope digest for evidence chain
            from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan

            envelope_dict = {
                "clearance": {
                    "thread_id": clearance.thread_id,
                    "action": clearance.action,
                    "nonce": clearance.nonce,
                    "governance_decision_digest": clearance.governance_decision_digest,
                },
                "result": result_msg,
            }
            envelope_digest = hashlib.sha256(
                jcs_canonicalize_plan(envelope_dict)
            ).hexdigest()

            return ActuationReceipt(
                accepted=True,
                receipt_id=receipt_id,
                session_uuid=clearance.thread_id,
                raw_receipt={
                    "clearance_nonce": clearance.nonce,
                    "governance_digest": clearance.governance_decision_digest,
                    "execution_result": result_msg,
                },
                findings=[],
                retryable=False,
                envelope_digest=envelope_digest,
                timestamp_utc=timestamp_utc,
            )

        except Exception as exc:
            logger.error("BrokerActuator: Trade execution failed: %s", exc)
            findings.append(
                {
                    "code": "EXECUTION_FAILED",
                    "detail": str(exc),
                }
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=findings,
                retryable="INTERRUPTED" not in str(exc),  # Interrupts are not retryable
                timestamp_utc=timestamp_utc,
            )
