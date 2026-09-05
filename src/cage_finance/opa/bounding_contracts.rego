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

# OPA Policy Layer for Bounding Contracts B1-B10
#
# Provides declarative policy definitions that can be evaluated by OPA
# for trade governance decisions. These policies mirror the Python
# implementations in src/cage_finance/safety/bounding/.

package cage.finance.bounding

# Import shared utilities if available
import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------
# B1 - Single-Order Notional Cap
# ---------------------------------------------------------
deny_hard_block contains msg if {
    input.order_notional > input.limits.max_single_order_notional
    msg := sprintf("B1: Order notional %.2f exceeds cap %.2f", [
        input.order_notional,
        input.limits.max_single_order_notional,
    ])
}

# ---------------------------------------------------------
# B2 - Daily Drawdown Limit
# ---------------------------------------------------------
circuit_breaker contains msg if {
    input.current_drawdown > input.limits.max_daily_drawdown
    msg := sprintf("B2: Drawdown %.4f exceeds limit %.4f", [
        input.current_drawdown,
        input.limits.max_daily_drawdown,
    ])
}

# ---------------------------------------------------------
# B3 - Liquidity Depth Ratio
# ---------------------------------------------------------
deny_liquidity contains msg if {
    input.order_book_depth > 0
    depth_ratio := input.order_size / input.order_book_depth
    depth_ratio > input.limits.max_depth_ratio
    msg := sprintf("B3: Depth ratio %.4f exceeds limit %.4f", [
        depth_ratio,
        input.limits.max_depth_ratio,
    ])
}

deny_liquidity contains msg if {
    input.order_book_depth <= 0
    msg := "B3: Order book depth is zero or negative"
}

# ---------------------------------------------------------
# B4 - Counterparty Concentration
# ---------------------------------------------------------
deny_concentration contains msg if {
    input.total_exposure > 0
    concentration := input.counterparty_exposure / input.total_exposure
    concentration > input.limits.max_concentration
    msg := sprintf("B4: Concentration %.4f exceeds limit %.4f", [
        concentration,
        input.limits.max_concentration,
    ])
}

# ---------------------------------------------------------
# B5 - Volatility-Adjusted Sizing
# ---------------------------------------------------------
scale_volatility contains result if {
    volatility_factor := 1.0 + (input.atr_multiplier * input.current_volatility)
    max_allowed := input.base_order_size / volatility_factor
    input.requested_size > max_allowed
    result := {
        "scaled_size": max_allowed,
        "original_size": input.requested_size,
        "message": sprintf("B5: Size scaled from %.2f to %.2f", [
            input.requested_size,
            max_allowed,
        ]),
    }
}

# ---------------------------------------------------------
# B6 - High-Impact Delta Escalation
# ---------------------------------------------------------
escalate_hitl contains msg if {
    position_delta := abs(input.position_delta)
    position_delta > input.limits.high_impact_threshold
    msg := sprintf("B6: Delta %.2f exceeds HITL threshold %.2f", [
        position_delta,
        input.limits.high_impact_threshold,
    ])
}

# Helper function for absolute value (OPA doesn't have native abs)
abs(x) := x if x >= 0
abs(x) := -x if x < 0

# ---------------------------------------------------------
# B7 - Audit Sealing
# ---------------------------------------------------------
deny_evidence_stream contains msg if {
    not input.evidence_stream_available
    msg := "B7: Evidence Stream unavailable - trading halted (fail-closed)"
}

# ---------------------------------------------------------
# B8 - TWAP Slippage Bound
# ---------------------------------------------------------
deny_slippage contains msg if {
    input.benchmark_price > 0
    input.side == "buy"
    slippage := (input.execution_price - input.benchmark_price) / input.benchmark_price
    slippage > input.limits.max_slippage
    msg := sprintf("B8: Buy slippage %.4f exceeds limit %.4f", [
        slippage,
        input.limits.max_slippage,
    ])
}

deny_slippage contains msg if {
    input.benchmark_price > 0
    input.side == "sell"
    slippage := (input.benchmark_price - input.execution_price) / input.benchmark_price
    slippage > input.limits.max_slippage
    msg := sprintf("B8: Sell slippage %.4f exceeds limit %.4f", [
        slippage,
        input.limits.max_slippage,
    ])
}

deny_slippage contains msg if {
    input.benchmark_price <= 0
    msg := "B8: Invalid benchmark price"
}

# ---------------------------------------------------------
# B9 - Jurisdictional Filter
# ---------------------------------------------------------
# Regional restrictions (illustrative)
regional_restrictions := {
    "US_FED": {
        "blocked_assets": ["USDT"],
        "blocked_categories": ["synthetic_derivatives"],
    },
    "EU_ECB": {
        "blocked_assets": [],
        "blocked_categories": ["privacy_coins"],
    },
    "APAC_MAS": {
        "blocked_assets": [],
        "blocked_categories": ["leveraged_tokens"],
    },
    "LOCAL": {
        "blocked_assets": [],
        "blocked_categories": [],
    },
}

deny_jurisdiction contains msg if {
    region := input.deployment_region
    restrictions := regional_restrictions[region]
    input.symbol in restrictions.blocked_assets
    msg := sprintf("B9: Asset %s is blocked in region %s", [
        input.symbol,
        region,
    ])
}

deny_jurisdiction contains msg if {
    region := input.deployment_region
    restrictions := regional_restrictions[region]
    input.asset_category != ""
    input.asset_category in restrictions.blocked_categories
    msg := sprintf("B9: Asset category %s is blocked in region %s", [
        input.asset_category,
        region,
    ])
}

# ---------------------------------------------------------
# B10 - Rollback Window Validation
# ---------------------------------------------------------
deny_rollback contains msg if {
    input.terminal_classification == "EXTERNALLY_REVERSIBLE"
    not input.rollback_supported
    msg := "B10: Broker does not support rollback - re-classifying to IRREVERSIBLE_TERMINAL"
}

deny_rollback contains msg if {
    input.terminal_classification == "EXTERNALLY_REVERSIBLE"
    input.rollback_supported
    min_window := 60
    input.settlement_window_seconds < min_window
    msg := sprintf("B10: Settlement window %ds below minimum %ds - re-classifying to IRREVERSIBLE_TERMINAL", [
        input.settlement_window_seconds,
        min_window,
    ])
}

# ---------------------------------------------------------
# Composite Decision
# ---------------------------------------------------------
# Aggregate all denial reasons
all_denials := deny_hard_block |
              circuit_breaker |
              deny_liquidity |
              deny_concentration |
              deny_evidence_stream |
              deny_slippage |
              deny_jurisdiction |
              deny_rollback

# Trade is allowed if no denials exist
allow if {
    count(all_denials) == 0
    count(escalate_hitl) == 0
}

# Trade requires HITL review
requires_hitl if {
    count(escalate_hitl) > 0
}

# Trade should be scaled (B5)
should_scale if {
    count(scale_volatility) > 0
}
