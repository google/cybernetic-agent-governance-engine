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
# Authorization-claim escalation — hard gate (PR 4, defense-in-depth).
#
# Any request where the gateway layer's structural detector
# (authorization_claim_detector.py) found an authorization-claim pattern is
# routed to human review, regardless of action, amount, or role.
#
# Priority guarantee: this rule is expressed as a hard-negation guard on ALL
# execute_trade and market_analysis ALLOW rules below (each has
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
}

# ---------------------------------------------------------------------------
# Unknown / missing role — explicit deny (belt-and-suspenders, default covers
# this, but stated explicitly for audit clarity)
# (From: finance_policy.rego — RBAC guard)
# ---------------------------------------------------------------------------
allow = "DENY" if {
    input.action != "market_analysis"
    not lower(input.trader_role) in allowed_roles
}

# ---------------------------------------------------------------------------
# JUNIOR trader rules — RBAC is authoritative
# (From: finance_policy.rego — junior limits are the controlling constraint)
# ---------------------------------------------------------------------------

# Junior ALLOW: ≤ $5 000, non-BTC
# Guard: not allowed when an authorization claim is present (defer to MANUAL_REVIEW).
allow = "ALLOW" if {
    input.action == "execute_trade"
    lower(input.trader_role) == "junior"
    input.amount <= 5000
    input.currency != "BTC"
    not input.claimed_authorization_present
}

# Junior MANUAL_REVIEW: $5 001 – $10 000, non-BTC
allow = "MANUAL_REVIEW" if {
    input.action == "execute_trade"
    lower(input.trader_role) == "junior"
    input.amount > 5000
    input.amount <= 10000
    input.currency != "BTC"
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

# Senior ALLOW: ≤ $500 000, non-BTC
# (finance_policy.rego senior limit; consistent with trade_policy.rego
#  manual_review boundary — no conflict for senior traders at this threshold)
# Guard: not allowed when an authorization claim is present (defer to MANUAL_REVIEW).
allow = "ALLOW" if {
    input.action == "execute_trade"
    lower(input.trader_role) == "senior"
    input.amount <= 500000
    input.currency != "BTC"
    not input.claimed_authorization_present
}

# Senior MANUAL_REVIEW: $500 001 – $1 000 000, non-BTC
# (From: finance_policy.rego — preserves human-in-the-loop for large trades)
allow = "MANUAL_REVIEW" if {
    input.action == "execute_trade"
    lower(input.trader_role) == "senior"
    input.amount > 500000
    input.amount <= 1000000
    input.currency != "BTC"
}

# Senior DENY: > $1 000 000 (implicit via default)

# ---------------------------------------------------------------------------
# Risk profile rules — semantic mapping
# (From: finance_policy.rego — risk profile shielding)
# CAVEAT: These rules fire independently of RBAC; they are secondary controls
# that gate non-trade actions (e.g. portfolio rebalancing advice).  For
# execute_trade the RBAC rules above are the primary gate.
# ---------------------------------------------------------------------------

allow = "ALLOW" if {
    input.action != "execute_trade"
    lower(input.risk_profile) == "aggressive"
    not input.claimed_authorization_present
}

allow = "ALLOW" if {
    input.action != "execute_trade"
    lower(input.risk_profile) == "moderate"
    not input.claimed_authorization_present
}

allow = "ALLOW" if {
    input.action != "execute_trade"
    lower(input.risk_profile) == "conservative"
    not input.claimed_authorization_present
}

allow = "DENY" if {
    lower(input.risk_profile) == "speculative"
    not lower(input.trader_role) == "senior"
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

# Token quota exhausted → hard DENY (H-7: prevent uncapped resource consumption)
allow = "DENY" if {
    input.action == "execute_trade"
    quota := input.token_quota
    quota.quota_available == true
    quota.quota_exhausted == true
}

# Token quota below minimum reserve → degrade to MANUAL_REVIEW
# (preserves human oversight when budget is nearly exhausted)
allow = "MANUAL_REVIEW" if {
    input.action == "execute_trade"
    quota := input.token_quota
    quota.quota_available == true
    quota.quota_exhausted == false
    quota.below_min_reserve == true
    # Only override if primary RBAC gate would otherwise ALLOW
    # (avoid overriding existing DENY decisions)
    not _rbac_deny
}

# Internal helper: primary RBAC gate would deny this request
_rbac_deny if {
    input.action == "execute_trade"
    lower(input.trader_role) == "junior"
    input.amount > 10000
}

_rbac_deny if {
    input.action == "execute_trade"
    lower(input.trader_role) == "senior"
    input.amount > 1000000
}

_rbac_deny if {
    input.action != "market_analysis"
    not lower(input.trader_role) in allowed_roles
}

