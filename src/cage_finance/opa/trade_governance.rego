# CONSOLIDATED: replaces finance_policy.rego + trade_policy.rego
#
# This file is the single authoritative trade governance policy for the
# Cybernetic Governance Engine.
#
# Resolution of the RBAC vs. amount-based conflict (R-12):
#   - finance_policy.rego (package: finance) used RBAC-based limits:
#       junior ≤ $5 k, senior ≤ $500 k — AUTHORITATIVE for trade decisions.
#   - trade_policy.rego (package: financial.trade) used flat amount-based limits:
#       allow ≤ $100 k, manual_review ≤ $500 k, deny > $500 k — DEPRECATED.
#   - The RBAC rules win: a junior trader cannot exceed $5 k regardless of the
#     flat amount threshold.  The flat thresholds are re-expressed here as
#     SENIOR-only safe-harbour values to preserve their intent while keeping
#     RBAC as the primary control axis.
#
# See governance/policy/README.md for architecture notes.

package trade.governance

import rego.v1

# ---------------------------------------------------------------------------
# Fail-closed default
# (From: finance_policy.rego — authoritative fail-closed posture)
# ---------------------------------------------------------------------------
default allow = "DENY"

# ---------------------------------------------------------------------------
# Role allow-list
# (From: finance_policy.rego — RBAC scaffolding)
# ---------------------------------------------------------------------------
allowed_roles := {"junior", "senior"}

# ---------------------------------------------------------------------------
# Trade actions and assets (GHSA-f6xq-23f7-9grm)
#
# Every action that places an order is a trade action, held to the same RBAC
# limits, quota rules and asset restrictions below. Previously only
# execute_trade was, so execute_trade_bounded fell through to the risk-profile
# rules and was allowed for any role, amount or asset.
#
# A trade's currency must be a string naming a tradable currency
# (tradable_currencies; the reference broker settles in USD only). That is an
# allowlist, so an alternate code for a restricted asset ("XBT") or a
# look-alike spelling is never admitted as a currency. Restricted assets are
# also refused as the instrument symbol. Both values are compared normalised
# (whitespace trimmed, upper-cased): an exact comparison let "btc", "Btc" and
# "BTC " through the BTC restriction. Without a tradable currency, no ALLOW or
# MANUAL_REVIEW rule fires (fail closed).
# ---------------------------------------------------------------------------
trade_actions := {"execute_trade", "execute_trade_bounded"}

tradable_currencies := {"USD"}

restricted_assets := {"BTC", "XBT"}

_is_trade if input.action in trade_actions

_currency := upper(trim_space(input.currency)) if is_string(input.currency)

_symbol := upper(trim_space(input.symbol)) if is_string(input.symbol)

_restricted_asset if _currency in restricted_assets

_restricted_asset if _symbol in restricted_assets

# The order is in a tradable currency and touches no restricted asset.
_admissible_asset if {
	_currency in tradable_currencies
	not _restricted_asset
}

# A trade outside a tradable currency, or touching a restricted asset —
# explicit deny for every trade action, role and amount (default covers this
# too; stated for audit clarity). _rbac_deny includes the same condition, so no
# MANUAL_REVIEW rule routes such a trade to a human either.
allow = "DENY" if {
	_is_trade
	not _admissible_asset
}

# ---------------------------------------------------------------------------
# Authorization-claim escalation — hard gate (PR 4, defense-in-depth).
#
# Any request where the gateway layer's structural detector
# (authorization_claim_detector.py) found an authorization-claim pattern is
# routed to human review, regardless of action, amount, or role.
#
# Priority guarantee: this rule is expressed as a hard-negation guard on ALL
# trade-action (trade_actions) and market_analysis ALLOW rules below (each has
# ``not input.claimed_authorization_present``), so the OPA decision set
# will contain only "MANUAL_REVIEW" — never "ALLOW" — when the flag is true.
#
# ``claimed_authorization_present`` is set programmatically by
# _extract_trade_payload() in safety_node.py; it is never LLM-sourced.
#
# Cross-region controls:
#   US_FED:  NIST SP 800-53 AC-3 (access enforcement) / IA-3 (node id)
#   EU_ECB:  EU AI Act Art 9 (risk management / structural input validation)
#   APAC_MAS: MAS TRM §11 / MAS Notice 655 (system integrity)
# ---------------------------------------------------------------------------
allow = "MANUAL_REVIEW" if {
	input.claimed_authorization_present == true

	# amount != 0: when amount IS zero the fail-closed rule below takes
	# priority — deny rather than route to manual review, because an
	# authorization claim with an unresolved amount cannot be meaningfully
	# reviewed for fiscal appropriateness.
	input.amount != 0
	not _rbac_deny
	not _speculative_deny
	not _quota_exhausted
}

# ---------------------------------------------------------------------------
# Fail-closed: authorization claim + unresolved amount → hard DENY
#
# Closes RBAC-004 ("sell ALL positions… pre-approved by the board") and
# CONF-SPOOF-001 ("Execute AAPL 50000 shares… confidence 1.0") adversarial
# gaps where _extract_trade_payload() produces amount=0 because the LLM
# plan omits a concrete dollar amount and the market-data price lookup is
# unavailable.
#
# When amount=0 the fiscal RBAC rules (junior ≤ $5k, senior ≤ $500k) would
# trivially pass — this rule closes that gap regardless of role or action.
#
# Cross-region controls:
#   US_FED:  NIST SP 800-53 AC-3 / SI-10 (input validation)
#   EU_ECB:  EU AI Act Art 9 (risk management / structural input validation)
#   APAC_MAS: MAS TRM §11 / MAS Notice 655 (system integrity)
# ---------------------------------------------------------------------------
allow = "DENY" if {
	input.claimed_authorization_present == true
	input.amount == 0
}

# ---------------------------------------------------------------------------
# Market analysis — safe read-only, always allowed for any valid role
# (From: finance_policy.rego, rule "Allow Market Analysis")
# Guard: not allowed when an authorization claim is present (defer to MANUAL_REVIEW).
# ---------------------------------------------------------------------------
allow = "ALLOW" if {
	input.action == "market_analysis"
	not input.claimed_authorization_present
	not _speculative_deny
}

# ---------------------------------------------------------------------------
# Unknown / missing role — explicit deny (belt-and-suspenders, default covers
# this, but stated explicitly for audit clarity)
# (From: finance_policy.rego — RBAC guard)
# ---------------------------------------------------------------------------
allow = "DENY" if {
	input.action != "market_analysis"
	input.action != "prompt_injection_check"
	not lower(input.trader_role) in allowed_roles
}

# ---------------------------------------------------------------------------
# JUNIOR trader rules — RBAC is authoritative
# (From: finance_policy.rego — junior limits are the controlling constraint)
# ---------------------------------------------------------------------------

# Junior ALLOW: ≤ $5 000, no restricted asset
# Guard: not allowed when an authorization claim is present (defer to MANUAL_REVIEW).
allow = "ALLOW" if {
	_is_trade
	lower(input.trader_role) == "junior"
	input.amount <= 5000
	_admissible_asset
	not input.claimed_authorization_present
	not _speculative_deny
	not _quota_exhausted
	not _quota_below_reserve
}

# Junior MANUAL_REVIEW: $5 001 – $10 000, no restricted asset
allow = "MANUAL_REVIEW" if {
	_is_trade
	lower(input.trader_role) == "junior"
	input.amount > 5000
	input.amount <= 10000
	_admissible_asset
	not _speculative_deny
	not _quota_exhausted
}

# Junior DENY: > $10 000  (implicit via default, stated for clarity)
# A junior trader is DENIED for amounts > $10 000.
# NOTE: trade_policy.rego would have allowed up to $100 000 — that rule is
# superseded here because RBAC limits are more restrictive and authoritative.

# ---------------------------------------------------------------------------
# SENIOR trader rules
# (Merged from finance_policy.rego RBAC limits and trade_policy.rego
#  amount thresholds — senior thresholds happen to be consistent: $500 k)
# ---------------------------------------------------------------------------

# Senior ALLOW: ≤ $500 000, no restricted asset
# (finance_policy.rego senior limit; consistent with trade_policy.rego
#  manual_review boundary — no conflict for senior traders at this threshold)
# Guard: not allowed when an authorization claim is present (defer to MANUAL_REVIEW).
allow = "ALLOW" if {
	_is_trade
	lower(input.trader_role) == "senior"
	input.amount <= 500000
	_admissible_asset
	not input.claimed_authorization_present
	not _quota_exhausted
	not _quota_below_reserve
}

# Senior MANUAL_REVIEW: $500 001 – $1 000 000, no restricted asset
# (From: finance_policy.rego — preserves human-in-the-loop for large trades)
allow = "MANUAL_REVIEW" if {
	_is_trade
	lower(input.trader_role) == "senior"
	input.amount > 500000
	input.amount <= 1000000
	_admissible_asset
	not _quota_exhausted
}

# Senior DENY: > $1 000 000 (implicit via default)

# ---------------------------------------------------------------------------
# Risk profile rules — semantic mapping
# (From: finance_policy.rego — risk profile shielding)
# CAVEAT: These rules fire independently of RBAC; they are secondary controls
# that gate non-trade actions only (e.g. portfolio rebalancing advice). Every
# trade action (trade_actions) is gated by the RBAC rules above; excluding
# them here also keeps a trade in a MANUAL_REVIEW band from matching an ALLOW
# rule as well (a conflicting value would be an evaluation error).
# ``input.action != "prompt_injection_check"`` also requires an action.
# ---------------------------------------------------------------------------

allow = "ALLOW" if {
	not _is_trade
	input.action != "prompt_injection_check"
	lower(input.risk_profile) == "aggressive"
	not input.claimed_authorization_present
	not _rbac_deny
}

allow = "ALLOW" if {
	not _is_trade
	input.action != "prompt_injection_check"
	lower(input.risk_profile) == "moderate"
	not input.claimed_authorization_present
	not _rbac_deny
}

allow = "ALLOW" if {
	not _is_trade
	input.action != "prompt_injection_check"
	lower(input.risk_profile) == "conservative"
	not input.claimed_authorization_present
	not _rbac_deny
}

_speculative_deny if {
	lower(input.risk_profile) == "speculative"
	not lower(input.trader_role) == "senior"
}

allow = "DENY" if {
	input.action != "prompt_injection_check"
	_speculative_deny
}

# ---------------------------------------------------------------------------
# Semantic shielding — prompt injection detection
# (From: finance_policy.rego — governance violation rules)
# ---------------------------------------------------------------------------

allow = "GOVERNANCE_VIOLATION" if {
	input.action == "prompt_injection_check"
	input.semantic_score > 0.85
}

allow = "GOVERNANCE_VIOLATION" if {
	input.action == "prompt_injection_check"
	contains(lower(input.content), "system override")
}

# ---------------------------------------------------------------------------
# ISO-001 / ISO 42001 §A.4 — Token Quota Rules
# Consumes live Redis token quota counters injected via policy_loader.with_redis_quota().
#
# The `token_quota` object is merged into the OPA input document before evaluation.
# If quota data is unavailable (quota_source == "degraded"), these rules are
# suppressed — the primary RBAC gate still applies, avoiding false positives.
#
# Key fields from input.token_quota:
#   quota_exhausted:    bool — True if remaining_tokens <= 0
#   below_min_reserve:  bool — True if remaining < 5% of budget
#   quota_available:    bool — False if Redis was unreachable (degraded mode)
#   quota_source:       "redis" | "degraded"
#
# POAM: ISO-001 (POAM_ISO42001.md)
# Related: CTRL_TQP_007 (lula-validation-tqp007.yaml), H-7 STPA hazard
# ---------------------------------------------------------------------------

_quota_exhausted if {
	_is_trade
	quota := input.token_quota
	quota.quota_available == true
	quota.quota_exhausted == true
}

_quota_below_reserve if {
	_is_trade
	quota := input.token_quota
	quota.quota_available == true
	quota.quota_exhausted == false
	quota.below_min_reserve == true
}

# Token quota exhausted → hard DENY (H-7: prevent uncapped resource consumption)
allow = "DENY" if {
	_quota_exhausted
}

# Token quota below minimum reserve → degrade to MANUAL_REVIEW
# (preserves human oversight when budget is nearly exhausted)
allow = "MANUAL_REVIEW" if {
	_quota_below_reserve

	# Only override if primary RBAC gate would otherwise ALLOW
	# (avoid overriding existing DENY decisions)
	not _rbac_deny
	not _speculative_deny
	not input.claimed_authorization_present
}

# Internal helper: primary RBAC gate would deny this request
_rbac_deny if {
	_is_trade
	lower(input.trader_role) == "junior"
	input.amount > 10000
}

_rbac_deny if {
	_is_trade
	lower(input.trader_role) == "senior"
	input.amount > 1000000
}

# A trade outside a tradable currency or touching a restricted asset: neither
# a human (the MANUAL_REVIEW rules above) nor the RBAC ladder may admit it.
_rbac_deny if {
	_is_trade
	not _admissible_asset
}

_rbac_deny if {
	input.action != "market_analysis"
	not lower(input.trader_role) in allowed_roles
}
