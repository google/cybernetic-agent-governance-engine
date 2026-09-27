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

"""Finance domain threshold schema (`domains.finance` in `governance_thresholds.json`)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CbfThresholds(BaseModel):
    min_cash_balance: float = Field(
        ..., gt=0, description="Minimum cash balance floor (USD)."
    )
    gamma: float = Field(..., gt=0, lt=1, description="CBF decay factor g in (0,1).")


class DrawdownThresholds(BaseModel):
    limit: float = Field(
        ..., gt=0.0, lt=1.0, description="Max portfolio drawdown fraction [0,1)."
    )


class StpaThresholds(BaseModel):
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


class ConsensusThresholds(BaseModel):
    threshold_usd: float = Field(
        ..., gt=0, description="USD amount above which consensus check is triggered."
    )


class BoundingThresholds(BaseModel):
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
        description="B5 — Maximum volatility percentile (0–100).",
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


class FinanceThresholds(BaseModel):
    """Root schema for `domains.finance` in `config/governance_thresholds.json`."""

    cbf: CbfThresholds
    drawdown: DrawdownThresholds
    stpa: StpaThresholds
    consensus: ConsensusThresholds
    bounding: BoundingThresholds = Field(default_factory=BoundingThresholds)


__all__ = [
    "BoundingThresholds",
    "CbfThresholds",
    "ConsensusThresholds",
    "DrawdownThresholds",
    "FinanceThresholds",
    "StpaThresholds",
]
