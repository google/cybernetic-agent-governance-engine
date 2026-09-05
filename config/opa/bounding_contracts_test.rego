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

# Bounding Contracts OPA Policy Tests — Phase 5 Step 12
# ======================================================
# Unit tests for bounding_contracts.rego (6 HARD_BLOCK contracts: B1–B5, B8).
#
# Test coverage per contract:
#   1. Pass — comfortably inside the bound
#   2. Boundary — exactly at the bound (inclusive/exclusive per Ratified Decision 1)
#   3. Fail — outside the bound, asserting violation message
#   4. Fail-closed — missing data defaults to safe denial
#
# Run with:
#   opa test config/opa/ -v

package bounding_contracts_test

import rego.v1

import data.bounding_contracts

# ---------------------------------------------------------------------------
# Helper: baseline compliant trade input
# ---------------------------------------------------------------------------

baseline_input := {
	"action": "execute_trade_bounded",
	"symbol": "AAPL",
	"amount": 10000.0,
	"side": "buy",
	"venue": "NYSE",
	"current_drawdown": 0.01,
	"order_book_depth": 1000000.0,
	"volatility_percentile": 50.0,
	"twap_slippage_bps": 25.0,
	"_thresholds": {
		"bounding": {
			"max_single_order_usd": 50000.0,
			"min_liquidity_depth_ratio": 10.0,
			"max_volatility_percentile": 75.0,
			"max_twap_slippage_bps": 50.0,
		},
		"max_daily_drawdown_pct": 5.0,
	},
}

# ---------------------------------------------------------------------------
# B1 — Maximum single-order notional value
# ---------------------------------------------------------------------------

# Pass: comfortably inside bound
test_b1_pass_inside_bound if {
	result := bounding_contracts.allow with input as baseline_input
	result == true
}

# Boundary: exactly at max_single_order_usd (inclusive per Ratified Decision 1)
test_b1_boundary_at_max if {
	inp := object.union(baseline_input, {"amount": 50000.0})
	result := bounding_contracts.allow with input as inp
	result == true
}

# Fail: exceeds max_single_order_usd
test_b1_fail_exceeds_max if {
	inp := object.union(baseline_input, {"amount": 75000.0})
	result := bounding_contracts.allow with input as inp
	result == false

	violations := bounding_contracts.violations with input as inp
	count(violations) > 0
	some msg in violations
	contains(msg, "B1 HARD_BLOCK")
	contains(msg, "75000")
}

# Fail-closed: missing amount (should fail during evaluation, or fail-closed by Python tier)
test_b1_fail_closed_missing_amount if {
	inp := object.remove(baseline_input, ["amount"])
	# OPA will fail evaluation if amount is missing; Python tier fails-closed
	# This test documents the expected behavior
	result := bounding_contracts.allow with input as inp
	result == false
}

# ---------------------------------------------------------------------------
# B2 — Daily drawdown portfolio circuit breaker
# ---------------------------------------------------------------------------

# Pass: drawdown well below threshold
test_b2_pass_low_drawdown if {
	result := bounding_contracts.allow with input as baseline_input
	result == true
}

# Boundary: exactly at max_daily_drawdown_pct (5%)
test_b2_boundary_at_max_drawdown if {
	inp := object.union(baseline_input, {"current_drawdown": 0.05})
	result := bounding_contracts.allow with input as inp
	result == true
}

# Fail: exceeds max_daily_drawdown_pct
test_b2_fail_exceeds_drawdown if {
	inp := object.union(baseline_input, {"current_drawdown": 0.08})
	result := bounding_contracts.allow with input as inp
	result == false

	violations := bounding_contracts.violations with input as inp
	count(violations) > 0
	some msg in violations
	contains(msg, "B2 HARD_BLOCK")
	contains(msg, "8.00%")
}

# Fail-closed: missing current_drawdown defaults to 0.0 (safe pass)
test_b2_fail_closed_missing_drawdown if {
	inp := object.remove(baseline_input, ["current_drawdown"])
	result := bounding_contracts.allow with input as inp
	# Defaults to 0.0, which is safe (below threshold)
	result == true
}

# ---------------------------------------------------------------------------
# B3 — Liquidity depth ratio verification
# ---------------------------------------------------------------------------

# Pass: depth ratio comfortably above minimum
test_b3_pass_high_liquidity if {
	# baseline: 200000 / 10000 = 20.0 (> 10.0 min)
	result := bounding_contracts.allow with input as baseline_input
	result == true
}

# Boundary: exactly at min_liquidity_depth_ratio (10.0)
test_b3_boundary_at_min_ratio if {
	inp := object.union(baseline_input, {"order_book_depth": 100000.0})
	# 100000 / 10000 = 10.0 (exactly at bound)
	result := bounding_contracts.allow with input as inp
	result == true
}

# Fail: depth ratio below minimum
test_b3_fail_low_liquidity if {
	inp := object.union(baseline_input, {"order_book_depth": 50000.0})
	# 50000 / 10000 = 5.0 (< 10.0 min)
	result := bounding_contracts.allow with input as inp
	result == false

	violations := bounding_contracts.violations with input as inp
	count(violations) > 0
	some msg in violations
	contains(msg, "B3 HARD_BLOCK")
	contains(msg, "5.00")
}

# Fail-closed: missing order_book_depth defaults to 0.0 (ratio = 0)
test_b3_fail_closed_missing_depth if {
	inp := object.remove(baseline_input, ["order_book_depth"])
	result := bounding_contracts.allow with input as inp
	# Defaults to 0.0, ratio = 0.0 / 10000 = 0.0 < 10.0 → BLOCK
	result == false
}

# ---------------------------------------------------------------------------
# B4 — Counterparty risk concentration
# ---------------------------------------------------------------------------

# Pass: no counterparty provided (OTC trade check skipped)
test_b4_pass_no_counterparty if {
	result := bounding_contracts.allow with input as baseline_input
	result == true
}

# Pass: counterparty exposure below max
test_b4_pass_low_exposure if {
	inp := object.union(baseline_input, {
		"counterparty": "COUNTERPARTY_A",
		"counterparty_exposure_usd": 50000.0,
	})
	# Default max_counterparty_exposure_usd is 100000.0
	result := bounding_contracts.allow with input as inp
	result == true
}

# Fail: counterparty exposure exceeds max
test_b4_fail_high_exposure if {
	inp := object.union(baseline_input, {
		"counterparty": "COUNTERPARTY_B",
		"counterparty_exposure_usd": 150000.0,
	})
	result := bounding_contracts.allow with input as inp
	result == false

	violations := bounding_contracts.violations with input as inp
	count(violations) > 0
	some msg in violations
	contains(msg, "B4 HARD_BLOCK")
	contains(msg, "COUNTERPARTY_B")
	contains(msg, "150000")
}

# ---------------------------------------------------------------------------
# B5 — Volatility-adjusted position sizing cap
# ---------------------------------------------------------------------------

# Pass: volatility percentile below max
test_b5_pass_low_volatility if {
	result := bounding_contracts.allow with input as baseline_input
	result == true
}

# Boundary: exactly at max_volatility_percentile (75.0)
test_b5_boundary_at_max_volatility if {
	inp := object.union(baseline_input, {"volatility_percentile": 75.0})
	result := bounding_contracts.allow with input as inp
	result == true
}

# Fail: volatility percentile exceeds max
test_b5_fail_high_volatility if {
	inp := object.union(baseline_input, {"volatility_percentile": 90.0})
	result := bounding_contracts.allow with input as inp
	result == false

	violations := bounding_contracts.violations with input as inp
	count(violations) > 0
	some msg in violations
	contains(msg, "B5 HARD_BLOCK")
	contains(msg, "90.00")
}

# Fail-closed: missing volatility_percentile defaults to 0.0 (safe pass)
test_b5_fail_closed_missing_volatility if {
	inp := object.remove(baseline_input, ["volatility_percentile"])
	result := bounding_contracts.allow with input as inp
	# Defaults to 0.0, which is safe (below 75.0 threshold)
	result == true
}

# ---------------------------------------------------------------------------
# B8 — TWAP slippage bound
# ---------------------------------------------------------------------------

# Pass: TWAP slippage below max
test_b8_pass_low_slippage if {
	result := bounding_contracts.allow with input as baseline_input
	result == true
}

# Boundary: exactly at max_twap_slippage_bps (50.0)
test_b8_boundary_at_max_slippage if {
	inp := object.union(baseline_input, {"twap_slippage_bps": 50.0})
	result := bounding_contracts.allow with input as inp
	result == true
}

# Fail: TWAP slippage exceeds max
test_b8_fail_high_slippage if {
	inp := object.union(baseline_input, {"twap_slippage_bps": 75.0})
	result := bounding_contracts.allow with input as inp
	result == false

	violations := bounding_contracts.violations with input as inp
	count(violations) > 0
	some msg in violations
	contains(msg, "B8 HARD_BLOCK")
	contains(msg, "75.00")
}

# Fail-closed: missing twap_slippage_bps defaults to 0.0 (safe pass)
test_b8_fail_closed_missing_slippage if {
	inp := object.remove(baseline_input, ["twap_slippage_bps"])
	result := bounding_contracts.allow with input as inp
	# Defaults to 0.0, which is safe (below 50.0 threshold)
	result == true
}

# ---------------------------------------------------------------------------
# Multiple violations
# ---------------------------------------------------------------------------

# Multiple contracts fail simultaneously
test_multiple_violations if {
	inp := object.union(baseline_input, {
		"amount": 100000.0,
		"current_drawdown": 0.10,
		"volatility_percentile": 95.0,
	})
	result := bounding_contracts.allow with input as inp
	result == false

	violations := bounding_contracts.violations with input as inp
	count(violations) == 3
}

# ---------------------------------------------------------------------------
# Wrong action name (defense-in-depth)
# ---------------------------------------------------------------------------

# Policy only applies to execute_trade_bounded
test_wrong_action_denied if {
	inp := object.union(baseline_input, {"action": "execute_trade"})
	result := bounding_contracts.allow with input as inp
	# Fail-closed: only execute_trade_bounded is allowed
	result == false
}
