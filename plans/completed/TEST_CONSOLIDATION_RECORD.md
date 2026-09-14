# Test Consolidation Record — September 14, 2026

## Context
Consolidated task-specific test modules created for PR B milestone verification into canonical evergreen test suites, and archived completed implementation plans to eliminate LLM context pollution during repository searches.

## Phase 1: Plan Archival

Moved the following completed implementation plans to `plans/completed/`:

- `BRANCH_MERGE_PLAN.md` — Branch reconciliation coordination (completed Sept 2026)
- `MERGE_PLAN_2026-09-03.md` — Specific merge coordination for Sept 3, 2026
- `domain_extraction_implementation_plan.md` — Domain plugin extraction (completed in v3.0)
- `layer_inversion_remediation_plan.md` — Three-layer architecture refactor (completed in v3.0)
- `partner_linkedin_outreach.md` — External communication drafts
- `pytest_marker_remediation_plan.md` — Marker contract enforcement (completed)
- `refactoring_vendor_communications.md` — Vendor coordination drafts
- `TECHNICAL_REPORT_GAP_ANALYSIS.md` — Documentation audit working doc
- `TECHNICAL_REPORT_REMEDIATION_PLAN.md` — Documentation update plan
- `vendor_decoupling_implementation_plan.md` — Vendor neutrality refactor (completed in v3.0)

## Phase 2: Test Module Renaming

Renamed milestone-specific test modules to reflect their architectural purpose rather than historical PR context:

| Original Name | New Name | Rationale |
|---|---|---|
| `test_pr_b_plugin_seams.py` | `test_plugin_seam_architecture.py` | Tests verify permanent plugin registry contracts (overlay dirs, background tasks), not PR B milestone |
| `test_pr_b_regional_posture.py` | `test_regional_hitl_constants.py` | Tests verify regional HITL constant loading from baseline JSONs, applicable beyond PR B |

## Phase 3: Test Consolidation Analysis

### Tests Kept As-Is (Unique Coverage)

**`test_pr_b_layer_isolation.py`**: Retained because it provides:
- `test_g3_import_boundary_enforcement()`: Subprocess integration test of `check_import_boundaries.py` script (complements unit tests in `test_import_boundaries.py`)
- `test_gateway_files_have_no_cage_imports()`: Direct AST regex scan (independent validation)
- `test_plugin_seam_imports_are_kernel_only()`: AST scan of seam modules (`singletons.py`, `background_tasks.py`, `constants.py`)

These tests provide end-to-end validation and independent AST scanning that complements the unit tests in [`test_import_boundaries.py`](../../tests/test_import_boundaries.py) and [`test_architectural_invariants.py`](../../tests/test_architectural_invariants.py).

**Decision**: Keep `test_pr_b_layer_isolation.py` but rename to `test_layer_isolation_integration.py` to clarify it's an integration harness.

### Tests Deleted (Subsumed by Canonical Suites)

**`test_pr_b_null_components.py`**: Deleted because:
- All fail-closed contracts (`NullSafetyFilter`, `NullConsensusProvider`, `NullColdStore`) are fully tested in [`test_null_components.py`](../../tests/test_null_components.py)
- Plugin installation flow tests (`test_install_domain_components_prevents_double_installation`, `test_singletons_default_to_null_components`) are PR B-specific scaffolding, not permanent architectural invariants
- The canonical version provides comprehensive coverage of W1.5 and W1.6 contracts

## Phase 4: Security Audit Test Organization (Deferred)

Security audit test modules (`test_security_fixes.py`, `test_security_high_severity.py`, `test_security_medium_severity.py`, `test_low_severity_fixes.py`) remain in place for now.

**Future Refactoring Recommendation**: Reorganize by subsystem rather than audit severity:
- `tests/security/test_kms_remediations.py` — KMS key management security contracts
- `tests/security/test_cbf_safety_boundaries.py` — CBF fail-closed enforcement
- `tests/security/test_policy_integrity.py` — Rego drift detection, hash verification
- `tests/security/test_cache_timing_attacks.py` — Redis fail-closed, timing leak mitigations

This refactoring should occur after confirming all POAM items referencing these tests are closed.

## CI Impact

- No test collection changes — all renamed tests retain their pytest markers
- No import path changes for production code
- Git history preserved via `git mv` (tracked renames)

## Verification Commands

```bash
# Verify all markers present
uv run pytest tests/ --collect-only -q --no-cov -n0 | grep -E "test_plugin_seam|test_regional_hitl|test_layer_isolation"

# Verify test count unchanged
find tests/ -name "test_*.py" | wc -l

# Verify no broken imports
uv run pytest tests/test_plugin_seam_architecture.py -v
uv run pytest tests/test_regional_hitl_constants.py -v
uv run pytest tests/test_pr_b_layer_isolation.py -v
```
