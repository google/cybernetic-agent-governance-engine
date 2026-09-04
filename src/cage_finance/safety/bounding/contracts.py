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

"""Bounding contract implementations (B1-B10) for execute_trade_bounded.

Phase 5 implementation per plans/phase_5_autonomous_trading_plan.md.

All contracts follow the fail-closed principle:
- Missing/invalid thresholds → admitted=False
- Missing/unavailable providers → admitted=False
- Inclusive boundary conditions (per Ratified Decision 1)

Contract Severity Taxonomy:
- HARD_BLOCK: Safety invariant, must not be violated (B1, B2, B4, B7, B9, B10)
- HITL_ESCALATE: Requires human review before proceeding (B3, B5, B6, B8)
"""

import hashlib
import logging
import math
import time
from typing import Any, Optional

from src.cage_finance.safety.bounding.models import (
    BoundedTradeRequest,
    ContractResult,
    ContractSeverity,
)
from src.cage_finance.safety.bounding.providers import (
    MarketDataProvider,
    RollbackCapabilityProvider,
)
from src.gateway.governance.ftra.bounding_contract import BoundingContractEnforcer

logger = logging.getLogger(__name__)


# ============================================================================
# B1 — Maximum Single-Order Notional Value
# ============================================================================


def contract_b1_max_notional(
    request: BoundedTradeRequest, thresholds: dict[str, Any]
) -> ContractResult:
    """B1 — Maximum single-order notional value.

    Per Phase 5 Master Plan Section 4.1:
    - Severity: HARD_BLOCK (safety invariant)
    - Threshold: bounding.max_single_order_usd (from governance_thresholds.json)
    - Boundary: amount <= max_single_order_usd (inclusive, per Ratified Decision 1)

    Fail-closed semantics:
    - Missing threshold → admitted=False, HARD_BLOCK
    - Non-finite threshold → admitted=False, HARD_BLOCK

    Args:
        request: Bounded trade request to validate
        thresholds: Governance thresholds dict (expected key: "bounding.max_single_order_usd")

    Returns:
        ContractResult with admitted=True if amount <= threshold, else False
    """
    contract_id = "B1"

    # Extract threshold with fail-closed semantics
    try:
        max_notional = thresholds.get("bounding", {}).get("max_single_order_usd")
    except (AttributeError, TypeError):
        max_notional = None

    if max_notional is None:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[
                {
                    "reason": "Missing threshold configuration",
                    "threshold_key": "bounding.max_single_order_usd",
                    "error": "Threshold not found in governance_thresholds.json",
                }
            ],
        )

    if not math.isfinite(max_notional):
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[
                {
                    "reason": "Invalid threshold value",
                    "threshold_key": "bounding.max_single_order_usd",
                    "threshold_value": max_notional,
                    "error": "Threshold must be finite",
                }
            ],
        )

    # Inclusive boundary check: amount <= max_notional (Ratified Decision 1)
    if request.amount <= max_notional:
        return ContractResult(
            contract_id=contract_id,
            admitted=True,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[],
        )

    # Violation: amount > max_notional
    return ContractResult(
        contract_id=contract_id,
        admitted=False,
        severity=ContractSeverity.HARD_BLOCK,
        findings=[
            {
                "reason": "Trade notional exceeds maximum single-order limit",
                "symbol": request.symbol,
                "amount_usd": request.amount,
                "limit_usd": max_notional,
                "excess_usd": request.amount - max_notional,
            }
        ],
    )


# ============================================================================
# B2 — Daily Drawdown Portfolio Circuit Breaker
# ============================================================================


def contract_b2_drawdown_breaker(
    request: BoundedTradeRequest,
    thresholds: dict[str, Any],
    current_drawdown: Optional[float] = None,
) -> ContractResult:
    """B2 — Daily drawdown portfolio circuit breaker.

    Per Phase 5 Master Plan Section 4.2:
    - Severity: HARD_BLOCK (safety invariant)
    - Threshold: drawdown.max_daily_drawdown_pct (from governance_thresholds.json)
    - Boundary: current_drawdown <= max_daily_drawdown_pct (inclusive)

    Fail-closed semantics:
    - Missing threshold → admitted=False, HARD_BLOCK
    - current_drawdown=None and CAGE_ENV=production → admitted=False, HARD_BLOCK
    - Non-finite threshold or drawdown → admitted=False, HARD_BLOCK

    Args:
        request: Bounded trade request to validate
        thresholds: Governance thresholds dict
        current_drawdown: Current portfolio drawdown percentage (0-100), None if unavailable

    Returns:
        ContractResult with admitted=True if drawdown is within threshold, else False
    """
    contract_id = "B2"

    # Extract threshold with fail-closed semantics
    try:
        max_drawdown_pct = thresholds.get("drawdown", {}).get("limit")
        if max_drawdown_pct is None:
            max_drawdown_pct = thresholds.get("drawdown", {}).get("max_daily_drawdown_pct")
    except (AttributeError, TypeError):
        max_drawdown_pct = None

    if max_drawdown_pct is None:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[
                {
                    "reason": "Missing threshold configuration",
                    "threshold_key": "drawdown.limit",
                    "error": "Threshold not found in governance_thresholds.json",
                }
            ],
        )

    if not math.isfinite(max_drawdown_pct):
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[
                {
                    "reason": "Invalid threshold value",
                    "threshold_key": "drawdown.limit",
                    "threshold_value": max_drawdown_pct,
                    "error": "Threshold must be finite",
                }
            ],
        )

    # Fail-closed: current_drawdown unavailable
    if current_drawdown is None:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[
                {
                    "reason": "Missing current drawdown data",
                    "symbol": request.symbol,
                    "error": "Cannot verify circuit breaker condition without current drawdown",
                }
            ],
        )

    if not math.isfinite(current_drawdown):
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[
                {
                    "reason": "Invalid current drawdown value",
                    "current_drawdown": current_drawdown,
                    "error": "Drawdown must be finite",
                }
            ],
        )

    # Inclusive boundary check: current_drawdown <= max_drawdown_pct
    if current_drawdown <= max_drawdown_pct:
        return ContractResult(
            contract_id=contract_id,
            admitted=True,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[],
        )

    # Violation: circuit breaker triggered
    cur_pct = current_drawdown * 100.0 if current_drawdown <= 1.0 else current_drawdown
    lim_pct = max_drawdown_pct * 100.0 if max_drawdown_pct <= 1.0 else max_drawdown_pct
    return ContractResult(
        contract_id=contract_id,
        admitted=False,
        severity=ContractSeverity.HARD_BLOCK,
        findings=[
            {
                "reason": "Portfolio drawdown exceeds circuit breaker limit",
                "symbol": request.symbol,
                "current_drawdown_pct": cur_pct,
                "limit_pct": lim_pct,
                "excess_pct": cur_pct - lim_pct,
            }
        ],
    )


# ============================================================================
# B6 — Mandatory HITL Escalation for High-Impact Deltas
# ============================================================================


def contract_b6_hitl_high_impact(
    request: BoundedTradeRequest, thresholds: dict[str, Any]
) -> ContractResult:
    """B6 — Mandatory HITL escalation for high-impact deltas.

    Per Phase 5 Master Plan Section 4.6:
    - Severity: HITL_ESCALATE (requires human review)
    - Threshold: confidence.min_threshold (from governance_thresholds.json)
    - Condition: If confidence < threshold → requires HITL review

    Fail-closed semantics:
    - Missing threshold → admitted=False, HITL_ESCALATE
    - Non-finite confidence → admitted=False, HITL_ESCALATE

    Args:
        request: Bounded trade request to validate
        thresholds: Governance thresholds dict

    Returns:
        ContractResult with admitted=True if confidence >= threshold, else HITL_ESCALATE
    """
    contract_id = "B6"

    # Extract threshold with fail-closed semantics
    # Reuses consensus.threshold_usd (default 10000.0) per Phase 5 Plan Section 4.6
    try:
        threshold_usd = thresholds.get("consensus", {}).get("threshold_usd")
        if threshold_usd is None:
            threshold_usd = thresholds.get("bounding", {}).get("max_hitl_threshold_usd")
    except (AttributeError, TypeError):
        threshold_usd = None

    if threshold_usd is None:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Missing threshold configuration",
                    "threshold_key": "consensus.threshold_usd",
                    "error": "Threshold not found in governance_thresholds.json",
                }
            ],
        )

    if not math.isfinite(threshold_usd):
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Invalid threshold value",
                    "threshold_key": "consensus.threshold_usd",
                    "threshold_value": threshold_usd,
                    "error": "Threshold must be finite",
                }
            ],
        )

    # Inclusive boundary: request.amount <= threshold_usd -> admitted
    if request.amount <= threshold_usd:
        return ContractResult(
            contract_id=contract_id,
            admitted=True,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[],
        )

    # High impact -> escalate to human review
    finding: dict[str, Any] = {
        "reason": "High-impact trade requires human review",
        "symbol": request.symbol,
        "amount_usd": request.amount,
        "threshold_usd": threshold_usd,
        "excess_usd": request.amount - threshold_usd,
    }
    if request.jurisdiction:
        finding["jurisdiction"] = request.jurisdiction

    return ContractResult(
        contract_id=contract_id,
        admitted=False,
        severity=ContractSeverity.HITL_ESCALATE,
        findings=[finding],
    )


# ============================================================================
# B3 — Liquidity Depth Ratio Verification
# ============================================================================


def contract_b3_liquidity_depth(
    request: BoundedTradeRequest,
    thresholds: dict[str, Any],
    market_data_provider: MarketDataProvider,
) -> ContractResult:
    """B3 — Liquidity depth ratio verification.

    Per Phase 5 Master Plan Section 4.3:
    - Severity: HITL_ESCALATE (requires human review for thin markets)
    - Threshold: bounding.min_liquidity_depth_ratio (from governance_thresholds.json)
    - Condition: (order_book_depth_usd / trade_amount) >= min_ratio

    Fail-closed semantics:
    - Missing threshold → admitted=False, HITL_ESCALATE
    - Provider unavailable → admitted=False, HITL_ESCALATE
    - Order book data unavailable → admitted=False, HITL_ESCALATE

    Args:
        request: Bounded trade request to validate
        thresholds: Governance thresholds dict
        market_data_provider: Market data provider for order book depth

    Returns:
        ContractResult with admitted=True if depth ratio >= threshold, else HITL_ESCALATE
    """
    contract_id = "B3"

    # Extract threshold with fail-closed semantics
    try:
        min_ratio = thresholds.get("bounding", {}).get("min_liquidity_depth_ratio")
    except (AttributeError, TypeError):
        min_ratio = None

    if min_ratio is None:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Missing threshold configuration",
                    "threshold_key": "bounding.min_liquidity_depth_ratio",
                    "error": "Threshold not found in governance_thresholds.json",
                }
            ],
        )

    if not math.isfinite(min_ratio) or min_ratio <= 0:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Invalid threshold value",
                    "threshold_key": "bounding.min_liquidity_depth_ratio",
                    "threshold_value": min_ratio,
                    "error": "Threshold must be finite and positive",
                }
            ],
        )

    # Query order book depth from provider
    try:
        depth_data = market_data_provider.get_order_book_depth(
            symbol=request.symbol, venue=request.venue, side=request.side
        )
    except RuntimeError as e:
        # Provider unavailable → fail-closed with HITL escalation
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Market data provider unavailable",
                    "symbol": request.symbol,
                    "venue": request.venue,
                    "error": str(e),
                    "action": "Escalate to human review — cannot verify liquidity depth",
                }
            ],
        )

    # Validate depth data structure
    if not isinstance(depth_data, dict):
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Invalid order book depth data",
                    "symbol": request.symbol,
                    "venue": request.venue,
                    "error": "Provider returned malformed depth data",
                }
            ],
        )

    # Staleness check
    timestamp = depth_data.get("timestamp")
    max_staleness = thresholds.get("telemetry", {}).get("max_staleness_seconds", 300)
    if timestamp is None or (time.time() - timestamp) > max_staleness:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Market depth data is stale",
                    "symbol": request.symbol,
                    "venue": request.venue,
                }
            ],
        )

    depth_usd = depth_data.get("depth_usd")
    if depth_usd is None:
        depth_usd = depth_data.get("total_bid_usd", 0.0)

    if not math.isfinite(depth_usd) or depth_usd < 0:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Invalid order book depth value",
                    "symbol": request.symbol,
                    "depth_usd": depth_usd,
                    "error": "Bid depth must be finite and non-negative",
                }
            ],
        )

    # Calculate depth ratio (avoid division by zero)
    if request.amount <= 0:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Invalid trade amount",
                    "amount": request.amount,
                    "error": "Trade amount must be positive",
                }
            ],
        )

    depth_ratio = depth_usd / request.amount

    # Inclusive boundary: depth_ratio >= min_ratio → sufficient liquidity
    if depth_ratio >= min_ratio:
        return ContractResult(
            contract_id=contract_id,
            admitted=True,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[],
        )

    # Thin market → escalate to human review
    return ContractResult(
        contract_id=contract_id,
        admitted=False,
        severity=ContractSeverity.HITL_ESCALATE,
        findings=[
            {
                "reason": "Insufficient market liquidity depth",
                "symbol": request.symbol,
                "venue": request.venue,
                "depth_ratio": depth_ratio,
                "min_required_ratio": min_ratio,
                "depth_usd": depth_usd,
                "trade_amount_usd": request.amount,
                "action": "Escalate to human review — thin market risk",
            }
        ],
    )


# ============================================================================
# B5 — Volatility-Adjusted Position Sizing Cap
# ============================================================================


def contract_b5_volatility_sizing(
    request: BoundedTradeRequest,
    thresholds: dict[str, Any],
    market_data_provider: MarketDataProvider,
) -> ContractResult:
    """B5 — Volatility-adjusted position sizing cap.

    Per Phase 5 Master Plan Section 4.5:
    - Severity: HITL_ESCALATE (requires human review in volatile markets)
    - Threshold: bounding.max_volatility_percentile (from governance_thresholds.json)
    - Condition: volatility_percentile <= max_percentile

    Fail-closed semantics:
    - Missing threshold → admitted=False, HITL_ESCALATE
    - Provider unavailable → admitted=False, HITL_ESCALATE
    - Volatility data unavailable → admitted=False, HITL_ESCALATE

    Args:
        request: Bounded trade request to validate
        thresholds: Governance thresholds dict
        market_data_provider: Market data provider for volatility percentile

    Returns:
        ContractResult with admitted=True if volatility <= threshold, else HITL_ESCALATE
    """
    contract_id = "B5"

    # Extract threshold with fail-closed semantics
    try:
        max_percentile = thresholds.get("bounding", {}).get("max_volatility_percentile")
    except (AttributeError, TypeError):
        max_percentile = None

    if max_percentile is None:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Missing threshold configuration",
                    "threshold_key": "bounding.max_volatility_percentile",
                    "error": "Threshold not found in governance_thresholds.json",
                }
            ],
        )

    if not math.isfinite(max_percentile) or not (0 <= max_percentile <= 100):
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Invalid threshold value",
                    "threshold_key": "bounding.max_volatility_percentile",
                    "threshold_value": max_percentile,
                    "error": "Threshold must be in range [0, 100]",
                }
            ],
        )

    # Query volatility percentile from provider
    try:
        vol_window_days = thresholds.get("bounding", {}).get("volatility_window_days", 30)
        vol_data = market_data_provider.get_volatility_percentile(
            symbol=request.symbol, window_days=vol_window_days
        )
    except RuntimeError as e:
        # Provider unavailable → fail-closed with HITL escalation
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Market data provider unavailable",
                    "symbol": request.symbol,
                    "error": str(e),
                    "action": "Escalate to human review — cannot verify volatility",
                }
            ],
        )

    # Validate volatility data structure
    if not isinstance(vol_data, dict) or "percentile" not in vol_data:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Invalid volatility data",
                    "symbol": request.symbol,
                    "error": "Provider returned malformed volatility data",
                }
            ],
        )

    # Staleness check
    timestamp = vol_data.get("timestamp")
    max_staleness = thresholds.get("telemetry", {}).get("max_staleness_seconds", 300)
    if timestamp is None or (time.time() - timestamp) > max_staleness:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Volatility data is stale",
                    "symbol": request.symbol,
                }
            ],
        )

    current_percentile = vol_data.get("percentile", 100.0)
    if not math.isfinite(current_percentile):
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Invalid volatility percentile",
                    "symbol": request.symbol,
                    "percentile": current_percentile,
                    "error": "Percentile must be finite",
                }
            ],
        )

    # Inclusive boundary: current_percentile <= max_percentile → acceptable volatility
    if current_percentile <= max_percentile:
        return ContractResult(
            contract_id=contract_id,
            admitted=True,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[],
        )

    # High volatility → escalate to human review
    return ContractResult(
        contract_id=contract_id,
        admitted=False,
        severity=ContractSeverity.HITL_ESCALATE,
        findings=[
            {
                "reason": "Asset volatility exceeds maximum threshold",
                "symbol": request.symbol,
                "volatility_percentile": current_percentile,
                "max_percentile": max_percentile,
                "action": "Escalate to human review — volatile market conditions",
            }
        ],
    )


# ============================================================================
# B8 — TWAP Slippage Bound
# ============================================================================


def contract_b8_twap_slippage(
    request: BoundedTradeRequest,
    thresholds: dict[str, Any],
    market_data_provider: MarketDataProvider,
) -> ContractResult:
    """B8 — TWAP slippage bound.

    Per Phase 5 Master Plan Section 4.8:
    - Severity: HITL_ESCALATE (requires human review for high slippage)
    - Threshold: bounding.max_twap_slippage_bps (from governance_thresholds.json)
    - Condition: observed_slippage_bps <= max_slippage_bps

    Fail-closed semantics:
    - Missing threshold → admitted=False, HITL_ESCALATE
    - Provider unavailable → admitted=False, HITL_ESCALATE
    - TWAP data unavailable → admitted=False, HITL_ESCALATE

    Args:
        request: Bounded trade request to validate
        thresholds: Governance thresholds dict
        market_data_provider: Market data provider for TWAP slippage

    Returns:
        ContractResult with admitted=True if slippage <= threshold, else HITL_ESCALATE
    """
    contract_id = "B8"

    # Extract threshold with fail-closed semantics
    try:
        max_slippage_bps = thresholds.get("bounding", {}).get("max_twap_slippage_bps")
    except (AttributeError, TypeError):
        max_slippage_bps = None

    if max_slippage_bps is None:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Missing threshold configuration",
                    "threshold_key": "bounding.max_twap_slippage_bps",
                    "error": "Threshold not found in governance_thresholds.json",
                }
            ],
        )

    if not math.isfinite(max_slippage_bps) or max_slippage_bps < 0:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Invalid threshold value",
                    "threshold_key": "bounding.max_twap_slippage_bps",
                    "threshold_value": max_slippage_bps,
                    "error": "Threshold must be finite and non-negative",
                }
            ],
        )

    # Query TWAP slippage from provider
    try:
        twap_window_seconds = thresholds.get("bounding", {}).get("twap_window_seconds", 300)
        twap_data = market_data_provider.get_recent_twap(
            symbol=request.symbol,
            venue=request.venue,
            window_seconds=twap_window_seconds,
        )
    except RuntimeError as e:
        # Provider unavailable → fail-closed with HITL escalation
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Market data provider unavailable",
                    "symbol": request.symbol,
                    "venue": request.venue,
                    "error": str(e),
                    "action": "Escalate to human review — cannot verify TWAP slippage",
                }
            ],
        )

    # Validate TWAP data structure
    if not isinstance(twap_data, dict):
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Invalid TWAP data",
                    "symbol": request.symbol,
                    "venue": request.venue,
                    "error": "Provider returned malformed TWAP data",
                }
            ],
        )

    # Staleness check
    timestamp = twap_data.get("timestamp")
    max_staleness = thresholds.get("telemetry", {}).get("max_staleness_seconds", 300)
    if timestamp is None or (time.time() - timestamp) > max_staleness:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "TWAP data is stale",
                    "symbol": request.symbol,
                    "venue": request.venue,
                }
            ],
        )

    twap_price = twap_data.get("twap_price")
    current_mid = twap_data.get("current_mid")
    if twap_price is not None and twap_price <= 0:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "TWAP price is zero (cannot compute slippage)",
                    "symbol": request.symbol,
                    "venue": request.venue,
                }
            ],
        )

    if "slippage_bps" in twap_data:
        observed_slippage_bps = twap_data["slippage_bps"]
    elif twap_price is not None and current_mid is not None and twap_price > 0:
        observed_slippage_bps = abs(current_mid - twap_price) / twap_price * 10000.0
    else:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Invalid TWAP data",
                    "symbol": request.symbol,
                    "venue": request.venue,
                    "error": "Provider returned malformed TWAP data",
                }
            ],
        )

    if not math.isfinite(observed_slippage_bps):
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[
                {
                    "reason": "Invalid TWAP slippage value",
                    "symbol": request.symbol,
                    "slippage_bps": observed_slippage_bps,
                    "error": "Slippage must be finite",
                }
            ],
        )

    # Inclusive boundary: observed_slippage_bps <= max_slippage_bps → acceptable
    if observed_slippage_bps <= max_slippage_bps:
        return ContractResult(
            contract_id=contract_id,
            admitted=True,
            severity=ContractSeverity.HITL_ESCALATE,
            findings=[],
        )

    # High slippage → escalate to human review
    return ContractResult(
        contract_id=contract_id,
        admitted=False,
        severity=ContractSeverity.HITL_ESCALATE,
        findings=[
            {
                "reason": "TWAP slippage exceeds maximum threshold",
                "symbol": request.symbol,
                "venue": request.venue,
                "observed_slippage_bps": observed_slippage_bps,
                "slippage_bps": observed_slippage_bps,
                "max_slippage_bps": max_slippage_bps,
                "excess_bps": observed_slippage_bps - max_slippage_bps,
                "action": "Escalate to human review — excessive slippage risk",
            }
        ],
    )


# ============================================================================
# B4 — Counterparty Risk Concentration
# ============================================================================


def contract_b4_counterparty_concentration(
    request: BoundedTradeRequest, enforcer: BoundingContractEnforcer
) -> ContractResult:
    """B4 — Counterparty risk concentration.

    Per Phase 5 Master Plan Section 4.4:
    - Severity: HARD_BLOCK (safety invariant)
    - Enforcer: BoundingContractEnforcer (from FTRA boundary)
    - Validates counterparty against allowlist

    Args:
        request: Bounded trade request to validate
        enforcer: Bounding contract enforcer with counterparty allowlist

    Returns:
        ContractResult with admitted=True if counterparty is allowed, else False
    """
    contract_id = "B4"

    if request.counterparty is None:
        if not getattr(enforcer.config, "allowed_counterparties", []):
            return ContractResult(
                contract_id=contract_id,
                admitted=True,
                severity=ContractSeverity.HARD_BLOCK,
                findings=[],
            )
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[
                {
                    "reason": "Counterparty whitelist configured but trade has no counterparty",
                    "note": "OTC trades must specify counterparty when whitelist is active",
                    "symbol": request.symbol,
                    "error": "Counterparty must be specified for bounded trades",
                }
            ],
        )

    # Validate counterparty against enforcer allowlist
    if enforcer.validate_counterparty(request.counterparty):
        return ContractResult(
            contract_id=contract_id,
            admitted=True,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[],
        )

    # Counterparty not in allowlist → block
    return ContractResult(
        contract_id=contract_id,
        admitted=False,
        severity=ContractSeverity.HARD_BLOCK,
        findings=[
            {
                "reason": "Counterparty not in allowed whitelist",
                "symbol": request.symbol,
                "counterparty": request.counterparty,
                "action": "Counterparty must be approved before trading",
            }
        ],
    )


# ============================================================================
# B9 — Regional Regulatory Jurisdiction Filter
# ============================================================================


def contract_b9_jurisdiction_filter(
    request: BoundedTradeRequest, enforcer: BoundingContractEnforcer
) -> ContractResult:
    """B9 — Regional regulatory jurisdiction filter.

    Per Phase 5 Master Plan Section 4.9:
    - Severity: HARD_BLOCK (compliance invariant)
    - Enforcer: BoundingContractEnforcer (from FTRA boundary)
    - Validates venue against jurisdictional allowlist

    Args:
        request: Bounded trade request to validate
        enforcer: Bounding contract enforcer with venue allowlist

    Returns:
        ContractResult with admitted=True if venue is allowed, else False
    """
    contract_id = "B9"

    # Validate venue against enforcer allowlist
    if enforcer.validate_venue(request.venue):
        return ContractResult(
            contract_id=contract_id,
            admitted=True,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[],
        )

    # Venue not in allowlist → block
    return ContractResult(
        contract_id=contract_id,
        admitted=False,
        severity=ContractSeverity.HARD_BLOCK,
        findings=[
            {
                "reason": "Venue not allowed in current regulatory jurisdiction",
                "symbol": request.symbol,
                "venue": request.venue,
                "jurisdiction": request.jurisdiction,
                "note": "Regional compliance filter (B9) rejected execution venue",
            }
        ],
    )


# ============================================================================
# B7 — Audit Trail Cryptographic Hash Chain Sealing
# ============================================================================


def contract_b7_audit_trail_sealing(request: BoundedTradeRequest) -> ContractResult:
    """B7 — Audit trail cryptographic hash chain sealing.

    Per Phase 5 Master Plan Section 4.7:
    - Severity: HARD_BLOCK (audit integrity invariant)
    - Reuses KMS signer and provenance chain infrastructure
    - Fails closed if KMS signer module is unavailable

    Args:
        request: Bounded trade request to seal

    Returns:
        ContractResult with admitted=True if KMS signing is available
    """
    contract_id = "B7"

    # Capability check for KMS signer module
    try:
        import sys
        if (
            "src.gateway.governance.kms_signer" in sys.modules
            and sys.modules["src.gateway.governance.kms_signer"] is None
        ):
            raise ImportError("KMS signer module unavailable")
        from src.gateway.governance.kms_signer import KMSGovernanceSigner
        if KMSGovernanceSigner is None:
            raise ImportError("KMS signer module unavailable")
    except (ImportError, Exception) as e:
        return ContractResult(
            contract_id=contract_id,
            admitted=False,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[
                {
                    "reason": "KMS signer module unavailable",
                    "error": str(e),
                    "note": "Cannot execute unauditable trade",
                }
            ],
        )

    return ContractResult(
        contract_id=contract_id,
        admitted=True,
        severity=ContractSeverity.HARD_BLOCK,
        findings=[],
    )


# ============================================================================
# B10 — Rollback Window Validation
# ============================================================================


def contract_b10_rollback_window(
    request: BoundedTradeRequest,
    thresholds: dict[str, Any],
    rollback_provider: RollbackCapabilityProvider,
) -> tuple[ContractResult, Optional[str]]:
    """B10 — Rollback window validation.

    Per Phase 5 Master Plan Section 4.10:
    - Severity: HARD_BLOCK
    - Predicate: A cancel/unwind path exists AND rollback window is sufficient
    - Threshold key: bounding.b10_min_rollback_window_seconds
    - Provider: RollbackCapabilityProvider
    - Fail-closed: Unknown settlement deadline → block

    **CRITICAL**: B10 is the contract that justifies the EXTERNALLY_REVERSIBLE
    classification. If B10 fails, the action must be re-classified to
    IRREVERSIBLE_TERMINAL for that request (per Ratified Decision 2).

    Args:
        request: Bounded trade request to validate
        thresholds: Governance thresholds dictionary
        rollback_provider: Provider for venue rollback capabilities

    Returns:
        Tuple of (ContractResult, Optional[classification_override]):
        - ContractResult with admitted=True if rollback window is sufficient
        - classification_override="IRREVERSIBLE_TERMINAL" if B10 fails, else None
    """
    contract_id = "B10"

    # Validate threshold presence
    min_rollback_window_seconds = thresholds.get("bounding", {}).get(
        "b10_min_rollback_window_seconds"
    )
    if min_rollback_window_seconds is None:
        return (
            ContractResult(
                contract_id=contract_id,
                admitted=False,
                severity=ContractSeverity.HARD_BLOCK,
                findings=[
                    {
                        "reason": "Missing threshold: bounding.b10_min_rollback_window_seconds",
                        "symbol": request.symbol,
                    }
                ],
            ),
            "IRREVERSIBLE_TERMINAL",  # Re-classify upward
        )

    # Validate threshold is non-negative
    if not isinstance(min_rollback_window_seconds, (int, float)) or min_rollback_window_seconds < 0:
        return (
            ContractResult(
                contract_id=contract_id,
                admitted=False,
                severity=ContractSeverity.HARD_BLOCK,
                findings=[
                    {
                        "reason": "Invalid threshold: bounding.b10_min_rollback_window_seconds must be non-negative",
                        "symbol": request.symbol,
                        "threshold_value": min_rollback_window_seconds,
                    }
                ],
            ),
            "IRREVERSIBLE_TERMINAL",  # Re-classify upward
        )

    # Query rollback capability from provider
    try:
        capability = rollback_provider.verify_rollback_window(
            venue=request.venue,
            rollback_window_seconds=request.rollback_window_seconds,
        )
    except RuntimeError as e:
        # Provider unavailable → fail-closed with re-classification
        return (
            ContractResult(
                contract_id=contract_id,
                admitted=False,
                severity=ContractSeverity.HARD_BLOCK,
                findings=[
                    {
                        "reason": "Rollback capability provider unavailable",
                        "symbol": request.symbol,
                        "venue": request.venue,
                        "error": str(e),
                        "note": "Cannot verify reversibility — re-classifying to IRREVERSIBLE_TERMINAL",
                    }
                ],
            ),
            "IRREVERSIBLE_TERMINAL",  # Re-classify upward
        )

    # Validate venue supports rollback
    if not capability.get("supported", False):
        return (
            ContractResult(
                contract_id=contract_id,
                admitted=False,
                severity=ContractSeverity.HARD_BLOCK,
                findings=[
                    {
                        "reason": "Venue does not support rollback/cancellation",
                        "symbol": request.symbol,
                        "venue": request.venue,
                        "note": "No external reversibility path exists — re-classifying to IRREVERSIBLE_TERMINAL",
                    }
                ],
            ),
            "IRREVERSIBLE_TERMINAL",  # Re-classify upward
        )

    # Validate rollback API is operational
    if not capability.get("api_available", False):
        return (
            ContractResult(
                contract_id=contract_id,
                admitted=False,
                severity=ContractSeverity.HARD_BLOCK,
                findings=[
                    {
                        "reason": "Venue rollback API is not currently operational",
                        "symbol": request.symbol,
                        "venue": request.venue,
                        "note": "Cannot guarantee reversibility — re-classifying to IRREVERSIBLE_TERMINAL",
                    }
                ],
            ),
            "IRREVERSIBLE_TERMINAL",  # Re-classify upward
        )

    # Validate rollback window is sufficient (inclusive boundary)
    max_window_seconds = capability.get("max_window_seconds", 0)
    if request.rollback_window_seconds > max_window_seconds:
        return (
            ContractResult(
                contract_id=contract_id,
                admitted=False,
                severity=ContractSeverity.HARD_BLOCK,
                findings=[
                    {
                        "reason": "Requested rollback window exceeds venue capability",
                        "symbol": request.symbol,
                        "venue": request.venue,
                        "requested_window_seconds": request.rollback_window_seconds,
                        "max_window_seconds": max_window_seconds,
                        "note": "Rollback window too long — re-classifying to IRREVERSIBLE_TERMINAL",
                    }
                ],
            ),
            "IRREVERSIBLE_TERMINAL",  # Re-classify upward
        )

    # Validate requested window meets minimum threshold (inclusive boundary per Ratified Decision 1)
    if request.rollback_window_seconds < min_rollback_window_seconds:
        return (
            ContractResult(
                contract_id=contract_id,
                admitted=False,
                severity=ContractSeverity.HARD_BLOCK,
                findings=[
                    {
                        "reason": "Requested rollback window below minimum threshold",
                        "symbol": request.symbol,
                        "venue": request.venue,
                        "requested_window_seconds": request.rollback_window_seconds,
                        "min_threshold_seconds": min_rollback_window_seconds,
                        "note": "Insufficient rollback window — re-classifying to IRREVERSIBLE_TERMINAL",
                    }
                ],
            ),
            "IRREVERSIBLE_TERMINAL",  # Re-classify upward
        )

    # All checks passed — rollback window is sufficient
    return (
        ContractResult(
            contract_id=contract_id,
            admitted=True,
            severity=ContractSeverity.HARD_BLOCK,
            findings=[],
        ),
        None,  # No classification override (remains EXTERNALLY_REVERSIBLE)
    )
