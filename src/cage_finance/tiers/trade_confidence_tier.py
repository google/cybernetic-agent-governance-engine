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

"""[CTRL_AGT_001] Regional trade-confidence floor (phase 1, order 1).

The kernel ``ConfidenceStage`` enforces the universal confidence band
(``confidence.agent_threshold``) for every action in every region. A
jurisdiction may require more before an AI agent executes a trade: the
effective ``domains.finance.confidence.min_trade_confidence`` (EU_ECB 0.97,
APAC_MAS 0.96, US_FED 0.95; see ``config/thresholds/{REGION}_BASELINE.json``).

This tier applies that floor to trade execution with the band semantics of
the kernel stage: a score below the floor needs human approval (HITL) when it
is at or above the universal ``confidence.defer_floor``, and defers
(DEFERRABLE) below it. A missing or malformed score is a HARD violation; the
kernel stage refuses it too, so this tier never relaxes that outcome.
"""

from __future__ import annotations

import math
from typing import Any

from src.gateway.governance.constants import GovernanceControl
from src.gateway.governance.contracts import ReadOnlyTier, Violation, ViolationKind
from src.gateway.governance.schemas.thresholds import get_confidence_defer_floor

#: Finance actions that execute a trade (``finance_cost_resolver`` charges them).
TRADE_EXECUTION_ACTIONS: frozenset[str] = frozenset(
    {"execute_trade", "execute_trade_bounded"}
)

_CONTROL = GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value


class TradeConfidenceTier(ReadOnlyTier):
    """Refuse trade execution below the region's confidence floor."""

    def __init__(self, min_trade_confidence: float) -> None:
        if (
            isinstance(min_trade_confidence, bool)
            or not isinstance(min_trade_confidence, (int, float))
            or not math.isfinite(min_trade_confidence)
            or not 0.0 < min_trade_confidence <= 1.0
        ):
            raise ValueError(
                "min_trade_confidence must be a finite number in (0, 1], "
                f"got {min_trade_confidence!r}"
            )
        self._floor = float(min_trade_confidence)

    @property
    def min_trade_confidence(self) -> float:
        return self._floor

    @property
    def tier_name(self) -> str:
        return "trade_confidence"

    @property
    def order(self) -> int:
        return 1

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action in TRADE_EXECUTION_ACTIONS

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        score = params.get("confidence") if isinstance(params, dict) else None
        if (
            isinstance(score, bool)
            or not isinstance(score, (int, float))
            or not math.isfinite(score)
            or not 0.0 <= score <= 1.0
        ):
            return [
                Violation(
                    tier=self.tier_name,
                    code="TRADE_CONFIDENCE_INVALID",
                    message=(
                        f"[{_CONTROL}] trade confidence {score!r} is missing or "
                        "not a number in [0, 1]"
                    ),
                    kind=ViolationKind.HARD,
                )
            ]
        if score >= self._floor:
            return []
        defer_floor = get_confidence_defer_floor()
        return [
            Violation(
                tier=self.tier_name,
                code="TRADE_CONFIDENCE_BELOW_FLOOR",
                message=(
                    f"[{_CONTROL}] trade confidence {score:.3f} is below the "
                    f"regional floor {self._floor:.3f}"
                ),
                kind=ViolationKind.DEFERRABLE
                if score < defer_floor
                else ViolationKind.HITL,
            )
        ]


__all__ = ["TRADE_EXECUTION_ACTIONS", "TradeConfidenceTier"]
