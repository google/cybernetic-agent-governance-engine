# DEPRECATED: This file has been superseded by trade_governance.rego
#
# The rules here conflicted with finance_policy.rego (RBAC-based limits).
# Specifically:
#   - This file (package: financial.trade) allowed trades ≤ $100 000 for ANY
#     role, and required manual review between $100 k and $500 k.
#   - finance_policy.rego (package: finance) limited junior traders to ≤ $5 000
#     and senior traders to ≤ $500 000.
#   - A junior trader's $90 000 trade was ALLOW here but DENY there — R-12.
#
# Resolution: The RBAC-based limits in finance_policy.rego are authoritative.
# The consolidated policy is at:
#   src/governed_financial_advisor/governance/policy/trade_governance.rego
#   (package: trade.governance)
#
# Do NOT add new rules to this file. It is retained for git history only.

package financial.trade

import rego.v1

# Stub — all decisions delegate to trade.governance.
# OPA does not support cross-package delegation natively; callers must be
# updated to query `trade.governance` directly.  See README.md.
default allow = false
