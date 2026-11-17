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

"""BrokerActuator — Finance Domain Execution Actuator (ADR-008 Phase 1 & 2)."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import time
from datetime import datetime, timezone
from typing import Protocol

from src.cage_finance.invariants import finance_cost_resolver
from src.cage_finance.models.trade_order import TradeOrder
from src.cage_finance.tools.trade_executor import (
    IndeterminateExecutionError,
    PreWireRejectionError,
    execute_trade,
)
from src.gateway.governance import routing_seal
from src.gateway.governance.seams.actuation import (
    ActuationOutcome,
    ActuationReceipt,
    ActuatorCapability,
    ExecutionClearance,
)
from src.gateway.infrastructure.config_manager import config_manager

logger = logging.getLogger(__name__)


class CustodianLedger(Protocol):
    def record_debit(
        self,
        amount_usd: float,
        *,
        submitted_at: float | None = None,
        debit_id: str | None = None,
    ) -> str: ...


class BrokerActuator:
    """
    Finance domain actuator for trade execution.

    Implements ExecutionActuator protocol to receive governance clearances
    and dispatch them to the broker execution layer.

    A fill is only *accepted* once it is journaled with the custodian ledger
    (ADR-010 §6): in the reference deployment that is the simulated custody
    cash ledger the reconciliation worker reads, so the debit surfaces in a
    reconciled snapshot after the settlement lag. ``accepted=True`` therefore
    means "the money moved", which is the event the CBF's local-debit ledger
    is waiting to see settle.

    Capabilities:
        - REPLAY_PROTECTED: Nonce-based replay prevention via routing seal
    """

    @property
    def actuator_id(self) -> str:
        """Unique identifier for this actuator."""
        return "cage_finance_broker"

    def __init__(self, ledger: CustodianLedger | None = None) -> None:
        self._ledger = ledger

    def _custodian_ledger(self) -> CustodianLedger:
        if self._ledger is None:
            from src.cage_finance.ground_truth import SimulatedCashLedgerProvider

            self._ledger = SimulatedCashLedgerProvider()
        return self._ledger

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
            use_mock = os.getenv("USE_MOCK_BROKER", "false").lower() in (
                "true",
                "1",
                "yes",
            )
            if use_mock:
                return True

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
        1. Validates the clearance, its quorum, and its out-of-band routing seal
           cryptographically (digest binding + verify_seal)
        2. Constructs TradeOrder from clearance parameters
        3. Invokes execute_trade with the routing seal (never the digest)
        4. Classifies pre-wire rejections as REJECTED and any post-transmission
           indeterminate error as UNKNOWN (retryable=False) so settlement never
           rolls back CBF or FiscalLimitGuard reservations after potential fill.
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
                outcome=ActuationOutcome.REJECTED,
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
                outcome=ActuationOutcome.REJECTED,
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
                outcome=ActuationOutcome.REJECTED,
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
                outcome=ActuationOutcome.REJECTED,
            )

        # Step 3: Cryptographically verify the out-of-band routing seal and its
        # binding to clearance.governance_decision_digest ([DA-02]).
        if (
            not clearance.routing_seal
            or not isinstance(clearance.routing_seal, str)
            or not clearance.routing_seal.strip()
        ):
            findings.append(
                {
                    "code": "MISSING_ROUTING_SEAL",
                    "detail": "the routing seal is required for actuation",
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
                outcome=ActuationOutcome.REJECTED,
            )

        computed_seal_digest = routing_seal.seal_digest(clearance.routing_seal)
        if not hmac.compare_digest(
            computed_seal_digest, clearance.governance_decision_digest
        ):
            findings.append(
                {
                    "code": "SEAL_DIGEST_MISMATCH",
                    "severity": "TERMINAL",
                    "detail": "routing_seal SHA-256 digest does not match clearance.governance_decision_digest",
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
                outcome=ActuationOutcome.REJECTED,
            )

        seal_params = dict(clearance.params)
        try:
            verified = routing_seal.verify_seal(
                clearance.routing_seal,
                clearance.action,
                seal_params,
            )
            if not verified:
                raise routing_seal.SymbolicGovernorViolation(
                    "verify_seal returned False",
                    action=clearance.action,
                )
        except routing_seal.SymbolicGovernorViolation as exc:
            logger.warning(
                "BrokerActuator: Routing seal cryptographic verification failed: %s",
                exc.reason,
            )
            findings.append(
                {
                    "code": "INVALID_ROUTING_SEAL",
                    "severity": "TERMINAL",
                    "detail": f"Routing seal verification failed: {exc.reason}",
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
                outcome=ActuationOutcome.REJECTED,
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
            order = TradeOrder(**seal_params)  # type: ignore[arg-type]
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
                outcome=ActuationOutcome.REJECTED,
            )

        # Step 5: Execute trade with the out-of-band routing seal ([DA-01])
        try:
            result_msg = await execute_trade(
                order,
                routing_seal=clearance.routing_seal,
                action=clearance.action,
                seal_params=seal_params,
            )

            receipt_id = clearance.nonce
            logger.info(
                "BrokerActuator: Trade executed successfully: %s",
                result_msg,
            )

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

            # Step 6: Journal the fill with the custodian so ground truth
            # settles it. The debit equals the CBF cost by construction
            # (same resolver), and the clearance nonce keys the entry.
            fill_amount = finance_cost_resolver(clearance.action, seal_params)
            if fill_amount > 0.0:
                try:
                    await asyncio.to_thread(
                        self._custodian_ledger().record_debit,
                        fill_amount,
                        submitted_at=time.time(),
                        debit_id=clearance.nonce,
                    )
                except Exception as journal_exc:
                    logger.error(
                        "BrokerActuator: custodian journal write failed: %s",
                        journal_exc,
                    )
                    findings.append(
                        {
                            "code": "CUSTODIAN_JOURNAL_FAILED",
                            "detail": str(journal_exc),
                        }
                    )
                    return ActuationReceipt(
                        accepted=False,
                        receipt_id=None,
                        session_uuid=clearance.thread_id,
                        raw_receipt=None,
                        findings=findings,
                        retryable=False,
                        timestamp_utc=timestamp_utc,
                        outcome=ActuationOutcome.UNKNOWN,
                    )

            return ActuationReceipt(
                accepted=True,
                receipt_id=receipt_id,
                session_uuid=clearance.thread_id,
                raw_receipt={
                    "clearance_nonce": clearance.nonce,
                    "governance_digest": clearance.governance_decision_digest,
                    "execution_result": result_msg,
                    "custodian_debit_usd": fill_amount,
                },
                findings=[],
                retryable=False,
                envelope_digest=envelope_digest,
                timestamp_utc=timestamp_utc,
                outcome=ActuationOutcome.ACCEPTED,
            )

        except routing_seal.SymbolicGovernorViolation as exc:
            logger.error("BrokerActuator: Pre-wire seal rejection: %s", exc)
            findings.append(
                {
                    "code": "INVALID_ROUTING_SEAL",
                    "severity": "TERMINAL",
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
                outcome=ActuationOutcome.REJECTED,
            )

        except PreWireRejectionError as exc:
            logger.warning(
                "BrokerActuator: Deterministic pre-execution rejection (%s): %s",
                exc.code,
                exc,
            )
            findings.append(
                {
                    "code": exc.code,
                    "severity": "TERMINAL",
                    "detail": str(exc),
                }
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=None,
                raw_receipt=None,
                findings=findings,
                retryable=exc.retryable,
                timestamp_utc=timestamp_utc,
                outcome=ActuationOutcome.REJECTED,
            )

        except IndeterminateExecutionError as exc:
            logger.error(
                "BrokerActuator: Post-wire indeterminate execution failure (%s): %s",
                exc.code,
                exc,
            )
            findings.append(
                {
                    "code": exc.code,
                    "severity": "INDETERMINATE",
                    "detail": str(exc),
                }
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=clearance.thread_id,
                raw_receipt=None,
                findings=findings,
                retryable=False,
                timestamp_utc=timestamp_utc,
                outcome=ActuationOutcome.UNKNOWN,
            )

        except Exception as exc:
            logger.error(
                "BrokerActuator: Unexpected post-precheck execution error (UNKNOWN): %s",
                exc,
            )
            findings.append(
                {
                    "code": "EXECUTION_INDETERMINATE",
                    "severity": "INDETERMINATE",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            )
            return ActuationReceipt(
                accepted=False,
                receipt_id=None,
                session_uuid=clearance.thread_id,
                raw_receipt=None,
                findings=findings,
                retryable=False,
                timestamp_utc=timestamp_utc,
                outcome=ActuationOutcome.UNKNOWN,
            )
