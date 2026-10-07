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

"""Finance domain threshold schema (`domains.finance` in `governance_thresholds.json`).

The kernel overlays the deployment region's `domains.finance` from
`config/thresholds/{REGION}_BASELINE.json` onto the global section and
validates the result with :class:`FinanceThresholds` at governor assembly.
Every model forbids unknown keys, so a misspelt regional override fails
assembly instead of silently leaving the global value in force.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator


class _FinanceSection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CbfThresholds(_FinanceSection):
    min_cash_balance: float = Field(
        ..., gt=0, description="Minimum cash balance floor (USD)."
    )
    gamma: float = Field(..., gt=0, lt=1, description="CBF decay factor g in (0,1).")


class DrawdownThresholds(_FinanceSection):
    limit: float = Field(
        ..., gt=0.0, lt=1.0, description="Max portfolio drawdown fraction [0,1)."
    )


class StpaThresholds(_FinanceSection):
    uca5_drawdown_threshold_pct: float = Field(
        ..., gt=0, description="UCA-5 drawdown % trigger (e.g. 4.5)."
    )
    uca6_max_order_volume_fraction: float = Field(
        ..., gt=0, lt=1, description="UCA-6 max order/daily-vol fraction."
    )
    max_sell_portfolio_fraction: float = Field(
        ..., gt=0, lt=1, description="FIN-1: max fraction of portfolio sold per order."
    )
    max_latency_ms: float = Field(
        ..., gt=0, description="FIN-2: max trade round-trip ms."
    )


class ConsensusThresholds(_FinanceSection):
    threshold_usd: float = Field(
        ..., gt=0, description="USD amount above which consensus check is triggered."
    )


class MinTradeConfidenceNorm(_FinanceSection):
    """[CTRL_AGT_001] The trade-confidence floor and its warrant requirement.

    ``requires_warrant`` is the region's decision: when true, CAGE relies on
    the floor only while the issuer's warrant for it verifies, and
    ``governing_version`` is the version that warrant must have been issued
    for. Changing ``value`` of a warranted norm requires a new
    ``governing_version`` and a re-issued warrant.
    """

    value: float = Field(
        ...,
        gt=0.0,
        le=1.0,
        description="Minimum agent confidence to execute a trade (0, 1].",
    )
    requires_warrant: StrictBool = Field(
        ...,
        description="Whether reliance on this floor needs a verified warrant.",
    )
    governing_version: str | None = Field(
        default=None,
        min_length=1,
        description="Governance version a warrant for this floor must name.",
    )

    @model_validator(mode="after")
    def _warranted_norm_names_a_version(self) -> MinTradeConfidenceNorm:
        if self.requires_warrant and self.governing_version is None:
            raise ValueError(
                "min_trade_confidence.requires_warrant needs a governing_version"
            )
        return self


class TradeConfidenceThresholds(_FinanceSection):
    """[CTRL_AGT_001] Regional floor on agent confidence for trade execution.

    Not the universal confidence band (`confidence.agent_threshold`): that
    band is region-neutral and enforced by the kernel for every action. This
    floor is a jurisdiction's requirement for trades only.
    """

    min_trade_confidence: MinTradeConfidenceNorm


class BoundingThresholds(_FinanceSection):
    enabled_contracts: list[str] = Field(
        default_factory=lambda: [
            "B1",
            "B2",
            "B3",
            "B4",
            "B5",
            "B6",
            "B7",
            "B8",
            "B9",
            "B10",
        ]
    )
    max_single_order_usd: float = Field(
        default=50000.0,
        gt=0,
        description="B1 — Maximum single-order notional value (USD).",
    )
    min_liquidity_depth_ratio: float = Field(
        default=10.0,
        gt=0,
        description="B3 — Minimum liquidity depth ratio (order_book_depth_usd / trade_amount).",
    )
    max_volatility_percentile: float = Field(
        default=75.0,
        ge=0.0,
        le=100.0,
        description="B5 — Maximum volatility percentile (0-100).",
    )
    volatility_window_days: int = Field(
        default=30,
        gt=0,
        description="B5 — Volatility observation window in days.",
    )
    max_twap_slippage_bps: float = Field(
        default=50.0,
        gt=0,
        description="B8 — Maximum TWAP slippage in basis points.",
    )
    twap_window_seconds: int = Field(
        default=300,
        gt=0,
        description="B8 — TWAP window duration in seconds.",
    )
    b10_min_rollback_window_seconds: int = Field(
        default=60,
        ge=60,
        description="B10 — Minimum rollback window in seconds.",
    )


class FinanceThresholds(_FinanceSection):
    """Root schema for the effective `domains.finance` section."""

    cbf: CbfThresholds
    drawdown: DrawdownThresholds
    stpa: StpaThresholds
    consensus: ConsensusThresholds
    confidence: TradeConfidenceThresholds
    bounding: BoundingThresholds = Field(default_factory=BoundingThresholds)


def load_finance_thresholds() -> FinanceThresholds:
    """The active region's effective `domains.finance`, schema-validated.

    Raises:
        KeyError: The thresholds carry no `domains.finance` section.
        pydantic.ValidationError: The section has an unknown, missing or
            out-of-range key.
    """
    from src.gateway.governance.schemas.thresholds import THRESHOLDS

    return FinanceThresholds.model_validate(THRESHOLDS.domains["finance"])


__all__ = [
    "BoundingThresholds",
    "CbfThresholds",
    "ConsensusThresholds",
    "DrawdownThresholds",
    "FinanceThresholds",
    "MinTradeConfidenceNorm",
    "StpaThresholds",
    "TradeConfidenceThresholds",
    "load_finance_thresholds",
]
