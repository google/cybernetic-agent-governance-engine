# CAGE STPA Multi-Source Layout

This STPA source layout is an illustrative pattern for adopters to manage multi-domain STPA models. The STPA control structure has been split into multiple domain-specific files for easier maintenance.

## File Structure

- `core_system.yaml`: Contains the core system model, generic hazards, non-financial control actions (like `write_db`), related UCAs, and generic safety constraints. This file serves as the base for the system model and is merged first.
- `domains/finance/trade_hazards.yaml`: Contains financial domain-specific hazards (e.g., unauthorized transactions, stale data), the `execute_trade` control action, related UCAs, safety constraints, and RBAC rules.

## Generating Artifacts

To regenerate artifacts from the multi-source layout, run:

```bash
uv run python -m src.gateway.governance.stpa_compiler compile --input-dir config/stpa/
```

## Merge Semantics

When the directory is loaded, the files are merged based on deterministic sorting of paths (`load_control_structures(sorted(paths))`).
- The `system` section of the first file (`core_system.yaml`) is authoritative and wins.
- Lists like `hazards`, `control_actions`, `unsafe_control_actions`, and `safety_constraints` are concatenated.
- Duplicate IDs across files are fatal and will fail compilation.
- Cross-file references (e.g., `hazard_refs` in UCAs) are resolved in the fully merged corpus. 

## Gate 1 Drift Oracle

The original monolithic `config/stpa_control_structure.yaml` file remains in the root `config/` directory. **Do not delete it.** It serves as the Gate 1 drift oracle for the system to validate backward compatibility and drift during the refactoring process (to be removed in PR 3).
