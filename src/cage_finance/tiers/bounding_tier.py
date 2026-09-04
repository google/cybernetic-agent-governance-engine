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

"""Bounding contract tier for execute_trade_bounded governance.

Phase 5 implementation per plans/phase_5_autonomous_trading_plan.md.
Evaluates all 10 bounding contracts (B1-B10) as a Phase 1 tier.
"""

import logging
from typing import Any, Optional

from src.cage_finance.safety.bounding.models import (
    BoundedTradeRequest,
    ContractResult,
    ContractSeverity,
)
from src.cage_finance.safety.bounding.registry import BoundingContractRegistry
from src.gateway.governance.contracts import GovernanceTierPlugin, Violation

logger = logging.getLogger(__name__)


class BoundingContractTierPlugin(GovernanceTierPlugin):
    """Bounding contract tier (phase 1, order 2).

    Evaluates all enabled bounding contracts (B1-B10) for execute_trade_bounded actions.
    Runs early in Phase 1 to fail-fast on safety/compliance invariants before heavier
    operations like CBF or causal analysis.

    Per Phase 5 Master Plan Section 3.1:
    - Position: Phase 1, order 2 (after FTRA boundary, before CBF)
    - Claims: execute_trade_bounded action only
    - Converts ContractResult → Violation
    - HARD_BLOCK severity → recoverable=False
    - HITL_ESCALATE severity → recoverable=True (parks in DeferQueue)
    """

    def __init__(self, registry: BoundingContractRegistry):
        """Initialize with bounding contract registry.

        Args:
            registry: BoundingContractRegistry orchestrating B1-B10
        """
        self.registry = registry
        self._classification_override: str | None = None

    @property
    def tier_name(self) -> str:
        return "bounding"

    @property
    def phase(self) -> int:
        return 1

    @property
    def order(self) -> int:
        # Order 2: After FTRA (order 1), before CBF (order 3)
        return 2

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        """Claim execute_trade_bounded action only."""
        return action == "execute_trade_bounded"

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        """Evaluate all enabled bounding contracts.

        Converts params dict to BoundedTradeRequest, runs registry.evaluate_all(),
        and converts ContractResult findings to Violation list.

        Args:
            action: Action name (must be "execute_trade_bounded")
            params: Action parameters containing trade details

        Returns:
            List of Violation for failed contracts
        """
        # Convert params to BoundedTradeRequest
        try:
            request = BoundedTradeRequest(
                symbol=params.get("symbol", ""),
                amount=float(params.get("amount", 0.0)),
                side=params.get("side", "buy"),
                venue=params.get("venue", ""),
                counterparty=params.get("counterparty"),
                trader_role=params.get("trader_role", "autonomous"),
                jurisdiction=params.get("jurisdiction"),
                rollback_window_seconds=int(params.get("rollback_window_seconds", 300)),
                transaction_id=params.get("transaction_id"),
            )
        except (ValueError, TypeError, KeyError) as e:
            logger.error("Failed to construct BoundedTradeRequest from params: %s", e)
            return [
                Violation(
                    tier=self.tier_name,
                    code="INVALID_REQUEST_PARAMS",
                    message=f"Invalid parameters for execute_trade_bounded: {e}",
                    recoverable=False,
                )
            ]

        # Evaluate all contracts via registry
        results, classification_override = self.registry.evaluate_all(request)
        self._classification_override = classification_override

        # Convert ContractResult list to Violation list
        violations: list[Violation] = []
        for result in results:
            if not result.admitted:
                violations.append(self._contract_result_to_violation(result))

        # Log classification override if present (for downstream FTRA re-classification)
        if classification_override:
            logger.warning(
                "Bounding tier emitted classification override: %s (B10 rollback window failure)",
                classification_override,
            )

        return violations

    async def commit(self, action: str, params: dict[str, Any]) -> list[Violation]:
        """No commit phase for bounding tier (evaluation only)."""
        return []

    async def rollback(self, action: str, params: dict[str, Any]) -> None:
        """No rollback state to release (stateless evaluation)."""
        pass

    def _contract_result_to_violation(self, result: ContractResult) -> Violation:
        """Convert ContractResult to Violation.

        Args:
            result: ContractResult from bounding contract evaluation

        Returns:
            Violation with appropriate code and recoverability
        """
        # Determine recoverability based on severity
        # HARD_BLOCK → recoverable=False (fail-closed, must abort)
        # HITL_ESCALATE → recoverable=True (parks in DeferQueue for human review)
        recoverable = result.severity == ContractSeverity.HITL_ESCALATE

        # Build violation message from findings
        if result.findings:
            # Use first finding's "reason" as primary message
            primary_finding = result.findings[0]
            message = primary_finding.get("reason", "Bounding contract failed")

            # Append additional context if available
            context_parts = []
            if "symbol" in primary_finding:
                context_parts.append(f"symbol={primary_finding['symbol']}")
            if "amount_usd" in primary_finding:
                context_parts.append(f"amount=${primary_finding['amount_usd']:,.2f}")
            if "limit_usd" in primary_finding:
                context_parts.append(f"limit=${primary_finding['limit_usd']:,.2f}")

            if context_parts:
                message = f"{message} ({', '.join(context_parts)})"
        else:
            message = f"Contract {result.contract_id} rejected request"

        return Violation(
            tier=self.tier_name,
            code=f"BOUNDING_{result.contract_id}_{result.severity.value}",
            message=message,
            recoverable=recoverable,
        )

    def get_classification_override(self) -> str | None:
        """Retrieve B10 classification override if emitted.

        Used by FTRA boundary to re-classify execute_trade_bounded from
        EXTERNALLY_REVERSIBLE → IRREVERSIBLE_TERMINAL when B10 fails.

        Returns:
            "IRREVERSIBLE_TERMINAL" if B10 failed, else None
        """
        return self._classification_override
