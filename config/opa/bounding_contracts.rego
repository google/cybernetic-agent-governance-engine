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

# Bounding Contracts OPA Policy — Phase 5 Defense-in-Depth
# =========================================================
# Enforces 6 HARD_BLOCK bounding contracts (B1, B2, B3, B4, B5, B8) for
# execute_trade_bounded actions. This policy runs alongside the Python
# BoundingContractTierPlugin as defense-in-depth.
#
# SCOPE: Only HARD_BLOCK severity contracts are encoded here.
#        HITL_ESCALATE contracts (B6) and capability checks (B7, B9, B10)
#        are handled exclusively by the Python tier.
#
# Input schema:
#   input.action              — Action name (must be "execute_trade_bounded")
#   input.symbol              — Ticker symbol
#   input.amount              — Trade notional value (USD)
#   input.side                — Trade direction ("buy" | "sell")
#   input.venue               — Execution venue
#   input.counterparty        — Counterparty identifier (optional)
#   input.current_drawdown    — Current daily drawdown (0.0–1.0, optional)
#   input.order_book_depth    — Order book depth USD (optional, for B3)
#   input.volatility_percentile — Volatility percentile 0–100 (optional, for B5)
#   input.twap_slippage_bps   — TWAP slippage in basis points (optional, for B8)
#   input._thresholds         — Governance thresholds from governance_thresholds.json
#
# Compliance: AISVS C9 (Action Taxonomy), ISO 42001 §A.5.3, NIST SP 800-53 SI-10

package bounding_contracts

import rego.v1

# ---------------------------------------------------------------------------
# Fail-closed default: deny unless all HARD_BLOCK contracts pass
# ---------------------------------------------------------------------------

default allow := false

# ---------------------------------------------------------------------------
# B1 — Maximum single-order notional value
# ---------------------------------------------------------------------------

violation_b1 := msg if {
	input.action == "execute_trade_bounded"
	max_notional := input._thresholds.bounding.max_single_order_usd
	input.amount > max_notional
	msg := sprintf(
		"B1 HARD_BLOCK: Trade amount %.2f USD exceeds maximum single-order notional %.2f USD",
		[input.amount, max_notional],
	)
}

# ---------------------------------------------------------------------------
# B2 — Daily drawdown portfolio circuit breaker
# ---------------------------------------------------------------------------

violation_b2 := msg if {
	input.action == "execute_trade_bounded"
	current_drawdown := object.get(input, "current_drawdown", 0.0)
	max_drawdown := object.get(input._thresholds, "max_daily_drawdown_pct", 5.0)
	current_drawdown_pct := current_drawdown * 100
	current_drawdown_pct > max_drawdown
	msg := sprintf(
		"B2 HARD_BLOCK: Current daily drawdown %.2f%% exceeds circuit breaker threshold %.2f%%",
		[current_drawdown_pct, max_drawdown],
	)
}

# ---------------------------------------------------------------------------
# B3 — Liquidity depth ratio verification
# ---------------------------------------------------------------------------

violation_b3 := msg if {
	input.action == "execute_trade_bounded"
	order_book_depth := object.get(input, "order_book_depth", 0.0)
	min_ratio := input._thresholds.bounding.min_liquidity_depth_ratio

	# Fail-closed: if order_book_depth is absent or zero, ratio is 0
	depth_ratio := order_book_depth / input.amount
	depth_ratio < min_ratio

	msg := sprintf(
		"B3 HARD_BLOCK: Liquidity depth ratio %.2f is below minimum %.2f (order book depth %.2f USD / trade amount %.2f USD)",
		[depth_ratio, min_ratio, order_book_depth, input.amount],
	)
}

# ---------------------------------------------------------------------------
# B4 — Counterparty risk concentration
# ---------------------------------------------------------------------------

violation_b4 := msg if {
	input.action == "execute_trade_bounded"
	counterparty := object.get(input, "counterparty", "")
	counterparty != ""

	# Note: Full B4 implementation requires querying existing exposure from ledger.
	# This OPA rule provides a structural check; the Python tier performs the
	# full calculation using the ledger provider.
	# For defense-in-depth, we enforce a fail-closed rule: if counterparty_exposure_usd
	# is provided in input and exceeds a threshold, block.
	counterparty_exposure := object.get(input, "counterparty_exposure_usd", 0.0)
	max_exposure := object.get(input._thresholds.bounding, "max_counterparty_exposure_usd", 100000.0)
	counterparty_exposure > max_exposure

	msg := sprintf(
		"B4 HARD_BLOCK: Counterparty '%s' exposure %.2f USD exceeds maximum %.2f USD",
		[counterparty, counterparty_exposure, max_exposure],
	)
}

# ---------------------------------------------------------------------------
# B5 — Volatility-adjusted position sizing cap
# ---------------------------------------------------------------------------

violation_b5 := msg if {
	input.action == "execute_trade_bounded"
	volatility_percentile := object.get(input, "volatility_percentile", 0.0)
	max_percentile := input._thresholds.bounding.max_volatility_percentile
	volatility_percentile > max_percentile
	msg := sprintf(
		"B5 HARD_BLOCK: Volatility percentile %.2f exceeds maximum %.2f",
		[volatility_percentile, max_percentile],
	)
}

# ---------------------------------------------------------------------------
# B8 — TWAP slippage bound
# ---------------------------------------------------------------------------

violation_b8 := msg if {
	input.action == "execute_trade_bounded"
	twap_slippage_bps := object.get(input, "twap_slippage_bps", 0.0)
	max_slippage_bps := input._thresholds.bounding.max_twap_slippage_bps
	twap_slippage_bps > max_slippage_bps
	msg := sprintf(
		"B8 HARD_BLOCK: TWAP slippage %.2f bps exceeds maximum %.2f bps",
		[twap_slippage_bps, max_slippage_bps],
	)
}

# ---------------------------------------------------------------------------
# Aggregate violations
# ---------------------------------------------------------------------------

violations := {msg |
	some msg in [
		violation_b1,
		violation_b2,
		violation_b3,
		violation_b4,
		violation_b5,
		violation_b8,
	]
}

# ---------------------------------------------------------------------------
# Allow if no violations
# ---------------------------------------------------------------------------

allow if {
	input.action == "execute_trade_bounded"
	count(violations) == 0
}

# ---------------------------------------------------------------------------
# Deny with reason (for debugging and audit trails)
# ---------------------------------------------------------------------------

deny := reasons if {
	input.action == "execute_trade_bounded"
	count(violations) > 0
	reasons := violations
}
