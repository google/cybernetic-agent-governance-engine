package system.authz
import rego.v1

# Deny access by default
default allow = false

# Allow access if the token provided matches the injected secret
allow if {
    input.identity == data.auth_token
}

# Minimum confidence when SLM is fully available
_min_confidence_normal := 0.95

# Elevated minimum confidence when SLM is unavailable
_min_confidence_slm_degraded := 0.97

# Derive the effective minimum confidence for this request
_effective_min_confidence := _min_confidence_slm_degraded if {
    input.slm_available == false
}
_effective_min_confidence := _min_confidence_normal if {
    input.slm_available != false
}

# Trade confidence check (only applied when action == execute_trade)
confidence_sufficient if {
    input.action == "execute_trade"
    confidence := object.get(input, "confidence", 0)
    confidence >= _effective_min_confidence
}

# Non-trade actions are not subject to the SLM-gated confidence rule
confidence_sufficient if {
    input.action != "execute_trade"
}

# Log-level metadata for audit — surfaced via OPA decision log
slm_degraded_warning := "SLM sidecar unavailable: elevated confidence threshold applied" if {
    input.slm_available == false
    input.action == "execute_trade"
}

# ── Token Quota Enforcement (ISO 42001 Annex A.4) ───────────────────────────
# CTRL_TQP_007 — secondary declarative evidence layer.
# Primary enforcement: TokenQuotaProxy (Python, Redis Lua).
# These rules activate when governance_middleware.py injects session state.
#
# C-10: Fail-closed defaults — missing fields are treated as over-limit/unknown.
# Removed permissive "if { not input.field }" clauses that defaulted to ALLOW
# when fields were absent. Use object.get with over-limit defaults instead.

_max_sequence_steps := 12
_max_tokens         := 100000

# Fail-closed: missing sequence_step_count → treat as over limit (deny).
_sequence_step_count := object.get(input, "sequence_step_count", _max_sequence_steps + 1)

quota_within_limits if {
    _sequence_step_count <= _max_sequence_steps
}

# Fail-closed: missing accumulated_tokens → treat as over limit (deny).
_accumulated_tokens := object.get(input, "accumulated_tokens", _max_tokens + 1)

token_quota_within_limits if {
    _accumulated_tokens <= _max_tokens
}

# ── Tool Allowlist (ISO 42001 Annex A.2) ────────────────────────────────────
_approved_tools := {
    "send_alert", "get_market_data", "execute_trade", "get_portfolio",
    "calculate_risk", "get_account_balance", "submit_order",
    "cancel_order", "get_order_status",
}

# Fail-closed: missing tool_name → treat as unknown tool (deny).
_tool_name := object.get(input, "tool_name", "__unknown__")

tool_approved if {
    _tool_name != "__unknown__"
    _tool_name in _approved_tools
}

# ── Combined governance allow rule ──────────────────────────────────────────
cage_systemic_governance_allow if {
    confidence_sufficient
    quota_within_limits
    token_quota_within_limits
    tool_approved
}
