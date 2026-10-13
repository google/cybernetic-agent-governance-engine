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

"""Financial domain-specific NeMo Guardrails actions."""

import math


def check_trade_risk_level(amount: float, asset: str) -> str:
    """Assess risk level for a proposed trade (fail-closed on invalid amount)."""
    if (
        isinstance(amount, bool)
        or not isinstance(amount, (int, float))
        or not math.isfinite(amount)
        or amount <= 0
        or not asset
    ):
        return "HIGH_RISK"
    if amount > 1000000:
        return "HIGH_RISK"
    if amount > 100000:
        return "MEDIUM_RISK"
    return "LOW_RISK"


def validate_market_hours(asset: str) -> bool:
    """Check if trading is allowed based on asset symbol presence."""
    return bool(asset and str(asset).strip())


def check_portfolio_exposure(asset: str, amount: float) -> str | None:
    """Verify portfolio exposure limits (fail-closed on invalid amount)."""
    if (
        isinstance(amount, bool)
        or not isinstance(amount, (int, float))
        or not math.isfinite(amount)
        or amount <= 0
    ):
        return "INVALID_EXPOSURE_AMOUNT"
    if amount > 1000000:
        return "EXPOSURE_LIMIT_EXCEEDED"
    return None
