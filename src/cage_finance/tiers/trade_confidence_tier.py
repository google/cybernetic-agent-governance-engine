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

The floor is declared to the kernel as a :class:`NormBinding`
(``confidence.min_trade_confidence``). The tier is built from that binding,
so the value it enforces is by construction the value the binding (and any
warrant for it) refers to. When the region marks the norm
``requires_warrant`` (EU_ECB), the kernel ``WarrantStage`` gates reliance on
it; a warrant failure (``RELIANCE_INELIGIBLE``) outranks every finding this
tier can raise except HARD, and a HARD here (a malformed score) is invalid
under any floor.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Any

from src.gateway.governance.constants import GovernanceControl
from src.gateway.governance.contracts import (
    NormBinding,
    ReadOnlyTier,
    Violation,
    ViolationKind,
)
from src.gateway.governance.schemas.thresholds import get_confidence_defer_floor

if TYPE_CHECKING:
    from src.cage_finance.thresholds import MinTradeConfidenceNorm

#: Finance actions that execute a trade (``finance_cost_resolver`` charges them).
TRADE_EXECUTION_ACTIONS: frozenset[str] = frozenset(
    {"execute_trade", "execute_trade_bounded"}
)

#: Issuer-facing identifier of the trade-confidence floor (warrant ``norm_id``).
TRADE_CONFIDENCE_NORM_ID = "confidence.min_trade_confidence"

_CONTROL = GovernanceControl.AGENT_CONFIDENCE_THRESHOLD.value


def trade_confidence_norm_binding(norm: MinTradeConfidenceNorm) -> NormBinding:
    """The kernel binding for the region's effective trade-confidence floor."""
    return NormBinding(
        norm_id=TRADE_CONFIDENCE_NORM_ID,
        value=norm.value,
        requires_warrant=norm.requires_warrant,
        actions=TRADE_EXECUTION_ACTIONS,
        governing_version=norm.governing_version,
    )


class TradeConfidenceTier(ReadOnlyTier):
    """Refuse trade execution below the region's confidence floor."""

    def __init__(self, norm: NormBinding) -> None:
        if (
            not isinstance(norm, NormBinding)
            or norm.norm_id != TRADE_CONFIDENCE_NORM_ID
        ):
            raise ValueError(
                f"TradeConfidenceTier needs the {TRADE_CONFIDENCE_NORM_ID!r} NormBinding"
            )
        if not 0.0 < norm.value <= 1.0:
            raise ValueError(
                "min_trade_confidence must be a finite number in (0, 1], "
                f"got {norm.value!r}"
            )
        self._norm = norm
        self._floor = float(norm.value)

    @property
    def norm_binding(self) -> NormBinding:
        """The binding whose value this tier enforces."""
        return self._norm

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


__all__ = [
    "TRADE_CONFIDENCE_NORM_ID",
    "TRADE_EXECUTION_ACTIONS",
    "TradeConfidenceTier",
    "trade_confidence_norm_binding",
]
