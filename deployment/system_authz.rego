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
