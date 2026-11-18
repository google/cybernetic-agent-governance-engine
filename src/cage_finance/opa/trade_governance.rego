# CONSOLIDATED: authoritative trade governance policy for CAGE finance plugin.
#
# Enforces:
#   1. Fail-closed default (`default allow := "DENY"`).
#   2. Strict action allowlisting across registered trade actions
#      (`execute_trade`, `execute_trade_bounded`), registered read-only/advisory
#      actions (`market_analysis`, `check_balance`, `check_market_status`), and
#      `prompt_injection_check` — arbitrary unregistered actions are always DENIED.
#   3. Strict numeric validation on `input.amount` (`is_number`, `not is_boolean`,
#      `input.amount > 0`) and cross-field consistency when `input.amount_minor`
#      is present (`round(input.amount * 100) == input.amount_minor`).
#   4. RBAC limits (`junior` <= $5k ALLOW / <= $10k MANUAL_REVIEW,
#      `senior` <= $500k ALLOW / <= $1M MANUAL_REVIEW), asset/currency allowlist,
#      authorization-claim escalation, and ISO-001 token-quota gating.

package trade.governance

import rego.v1

# ---------------------------------------------------------------------------
# Fail-closed default
# ---------------------------------------------------------------------------
default allow := "DENY"

# ---------------------------------------------------------------------------
# Registered roles, actions, currencies, and asset restrictions
# ---------------------------------------------------------------------------
allowed_roles := {"junior", "senior"}

trade_actions := {"execute_trade", "execute_trade_bounded"}

read_only_actions := {"market_analysis", "check_balance", "check_market_status"}

registered_advisory_actions := read_only_actions

tradable_currencies := {"USD"}

restricted_assets := {"BTC", "XBT"}

# ---------------------------------------------------------------------------
# Type-safe input extractors (immune to null/bool/number/object cross-type confusion)
# ---------------------------------------------------------------------------
_action := input.action if {
	is_object(input)
	is_string(input.action)
}

_role := lower(trim_space(input.trader_role)) if {
	is_object(input)
	is_string(input.trader_role)
}

_risk_profile := lower(trim_space(input.risk_profile)) if {
	is_object(input)
	is_string(input.risk_profile)
}

_currency := upper(trim_space(input.currency)) if {
	is_object(input)
	is_string(input.currency)
}

_symbol := upper(trim_space(input.symbol)) if {
	is_object(input)
	is_string(input.symbol)
}

_claimed_auth if {
	is_object(input)
	input.claimed_authorization_present == true
}

_is_trade if _action in trade_actions

_is_advisory if _action in registered_advisory_actions

# ---------------------------------------------------------------------------
# Strict numeric amount and amount_minor consistency validation ([DA-03])
# ---------------------------------------------------------------------------
_amount_minor_consistent if {
	is_object(input)
	object.get(input, "amount_minor", null) == null
}

_amount_minor_consistent if {
	is_object(input)
	raw_minor := object.get(input, "amount_minor", null)
	raw_minor != null
	is_number(raw_minor)
	not is_boolean(raw_minor)
	raw_minor > 0
	round(raw_minor) == raw_minor
	round(input.amount * 100) == raw_minor
}

_valid_trade_amount if {
	is_object(input)
	is_number(input.amount)
	not is_boolean(input.amount)
	input.amount > 0
	_amount_minor_consistent
}

# For read-only/advisory actions under claimed authorization: allow escalation to
# MANUAL_REVIEW only when no invalid/zero amount was attached (closes RBAC-004 /
# CONF-SPOOF-001 where unresolved amount=0 must hard-DENY).
_advisory_amount_ok_for_review if {
	is_object(input)
	not "amount" in object.keys(input)
}

_advisory_amount_ok_for_review if {
	_valid_trade_amount
}

# ---------------------------------------------------------------------------
# Asset & risk-profile guards
# ---------------------------------------------------------------------------
_restricted_asset if _currency in restricted_assets

_restricted_asset if _symbol in restricted_assets

_admissible_asset if {
	_currency in tradable_currencies
	not _restricted_asset
}

_speculative_deny if {
	_risk_profile == "speculative"
	_role != "senior"
}

# ---------------------------------------------------------------------------
# ISO-001 / ISO 42001 §A.4 — Token Quota Rules
# ---------------------------------------------------------------------------
_quota_exhausted if {
	_is_trade
	is_object(input)
	quota := object.get(input, "token_quota", null)
	is_object(quota)
	quota.quota_available == true
	quota.quota_exhausted == true
}

_quota_below_reserve if {
	_is_trade
	is_object(input)
	quota := object.get(input, "token_quota", null)
	is_object(quota)
	quota.quota_available == true
	quota.quota_exhausted == false
	quota.below_min_reserve == true
}

# ---------------------------------------------------------------------------
# Partition 1: Registered read-only / advisory actions
# (`market_analysis`, `check_balance`, `check_market_status`)
# ---------------------------------------------------------------------------
allow := "ALLOW" if {
	_is_advisory
	not _claimed_auth
	not _speculative_deny
}

allow := "MANUAL_REVIEW" if {
	_is_advisory
	_claimed_auth
	_advisory_amount_ok_for_review
	not _speculative_deny
}

# ---------------------------------------------------------------------------
# Partition 2: Registered trade actions (`execute_trade`, `execute_trade_bounded`)
# ---------------------------------------------------------------------------
_admissible_trade if {
	_is_trade
	_role in allowed_roles
	_valid_trade_amount
	_admissible_asset
	not _speculative_deny
	not _quota_exhausted
}

_within_allow_band if {
	_role == "junior"
	input.amount <= 5000
}

_within_allow_band if {
	_role == "senior"
	input.amount <= 500000
}

_in_manual_review_band if {
	_role == "junior"
	input.amount > 5000
	input.amount <= 10000
}

_in_manual_review_band if {
	_role == "senior"
	input.amount > 500000
	input.amount <= 1000000
}

_within_rbac_ceiling if _within_allow_band

_within_rbac_ceiling if _in_manual_review_band

allow := "ALLOW" if {
	_admissible_trade
	_within_allow_band
	not _claimed_auth
	not _quota_below_reserve
}

allow := "MANUAL_REVIEW" if {
	_admissible_trade
	_in_manual_review_band
}

allow := "MANUAL_REVIEW" if {
	_admissible_trade
	_within_rbac_ceiling
	_claimed_auth
}

allow := "MANUAL_REVIEW" if {
	_admissible_trade
	_within_rbac_ceiling
	_quota_below_reserve
}

# ---------------------------------------------------------------------------
# Partition 3: Semantic shielding — `prompt_injection_check`
# ---------------------------------------------------------------------------
_prompt_injection_violation if {
	is_object(input)
	is_number(input.semantic_score)
	not is_boolean(input.semantic_score)
	input.semantic_score > 0.85
}

_prompt_injection_violation if {
	is_object(input)
	is_string(input.content)
	contains(lower(input.content), "system override")
}

_prompt_injection_violation if {
	is_object(input)
	input.prompt_injection_verified == false
}

allow := "GOVERNANCE_VIOLATION" if {
	_action == "prompt_injection_check"
	_prompt_injection_violation
}

allow := "ALLOW" if {
	_action == "prompt_injection_check"
	is_number(input.semantic_score)
	not is_boolean(input.semantic_score)
	input.semantic_score >= 0
	input.semantic_score <= 0.85
	not _prompt_injection_violation
	not _claimed_auth
}
