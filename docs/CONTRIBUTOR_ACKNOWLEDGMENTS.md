# Contributor Acknowledgments

This document recognizes external contributors who have identified security issues, correctness bugs, and improvements in the CAGE reference architecture.

---

## Security Research Contributions

### Nussaibah Shaikh (@nussaibah-shaikh)

**Contributions:** August 2026

#### PR #93: Zero Balance Masking Bug
**Severity:** CRITICAL correctness issue

Discovered that the truthiness test `if not balance_value` in [`src/compliance_bridge/reconciliation_worker.py`](../src/compliance_bridge/reconciliation_worker.py) treated legitimate `0.0` balances as missing data, causing drained accounts to receive fallback balances. This would have allowed the CBF barrier `h(x) = cash - min_cash` to clear trades against empty accounts, silently undermining POAM-2026-023 reconciliation enforcement.

**Fix:** Modified `GcsLedgerProvider` and `ObjectStoreLedgerProvider` to use explicit `is None` checks, ensuring accurate 0.0 balances are returned.

**Test Coverage:** 26 tests with regression tests proving the bug.

#### PR #94: SPIFFE ID Keying Collision
**Severity:** HIGH — permission confusion vulnerability

Discovered that [`src/gateway/governance/opa.py`](../src/gateway/governance/opa.py) keyed the agent catalog on the last path segment of SPIFFE IDs instead of full identities. Two agents with SPIFFE IDs sharing a trailing segment (e.g., `spiffe://trust-domain-a/sa/trader-agent` and `spiffe://trust-domain-b/sa/trader-agent`) would collapse onto the same key, allowing the second entry to overwrite the first agent's permissions.

**Attack Vector:** An attacker could register an agent with a carefully chosen SPIFFE ID suffix to inherit another agent's grants.

**Fix:** Changed keying to full SPIFFE identity, aligning with how [`config/opa/agent_catalog.rego`](../config/opa/agent_catalog.rego) consumes the data.

**Test Coverage:** 58 tests with regression test `test_parse_registry_response_keys_on_full_spiffe_identity`.

---

### Miracle Owolabi (External Security Researcher, OWASP AI Exchange Author)

**Contributions:** August 2026

#### POAM-2026-023: External Reconciliation Not Enforced on Atomic Commit Path
**Severity:** CRITICAL — bypassed five separate controls

Discovered that `LUA_ATOMIC_CBF` read `safety:current_cash` directly instead of KMS-signed reconciled balance from `reconciliation:verified_balance`, bypassing:
1. KMS signature verification
2. `_CBF_STRICT_MODE` fail-closed behavior
3. R-04 replay sequence defense
4. TTL staleness rejection
5. R-05 fence-epoch validation

**Additional Findings:**
- Fence-epoch regression detection (R-05) was implemented but never executed on commit path
- Local debit tracking gap allowed double-spend within reconciliation window

**Remediation:** Created `_resolve_ground_truth_balance()` seam for KMS-verified balance resolution, modified `LUA_ATOMIC_CBF` to accept ground truth balance, added fence-epoch validation and local debit tracking on commit path.

**Test Coverage:** 5 new test cases in [`tests/test_cbf_reconciliation.py`](../tests/test_cbf_reconciliation.py).

---

## Impact Summary

| Contributor | PRs/Findings | Severity Distribution | Test Coverage Added |
|-------------|--------------|----------------------|---------------------|
| Nussaibah Shaikh | 2 PRs | 1 CRITICAL, 1 HIGH | 84 tests |
| Miracle Owolabi | 1 finding (POAM-2026-023) | 1 CRITICAL | 5 tests |

**Total Security/Correctness Issues Identified:** 3  
**Total Tests Added:** 89  
**Controls Strengthened:** AC-2, SC-4, SI-2, AU-12

---

## Recognition Policy

CAGE is a reference architecture with no production deployments to maintain. Contributors who identify security issues, correctness bugs, or architectural improvements are acknowledged here. This document serves as a record of community contributions to the reference design.

For questions about contributing security research, see [`SECURITY.md`](../SECURITY.md).
