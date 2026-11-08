# CAGE STPA Multi-Source Layout

This STPA source layout is the canonical source of truth for multi-domain STPA models (the legacy monolithic root YAML has been retired).

## File Structure

- `core_system.yaml`: Core system model, generic hazards, kernel control actions (`write_db`, `prompt_injection_check`, etc.), related UCAs, and generic safety constraints.
- `../../src/cage_finance/config/stpa/trade_hazards.yaml`: Finance domain-specific hazards, `execute_trade` / `execute_trade_bounded` UCAs, safety constraints, and RBAC metadata.

## Generating Artifacts

```bash
uv run python -m src.gateway.governance.stpa_compiler compile --input-dir config/stpa --targets nemo ftra sandbox
uv run python -m src.gateway.governance.stpa_compiler compile --domain-yaml src/cage_finance/config/stpa/trade_hazards.yaml --out-dir src/cage_finance/stpa
```

## Merge Semantics

When a directory or list of STPA files is loaded via `load_control_structures(sorted(paths))`:
- The `system` section of the first file (`core_system.yaml`) wins.
- Lists (`hazards`, `control_actions`, `unsafe_control_actions`, `safety_constraints`) are concatenated deterministically.
- Duplicate IDs or dangling `hazard_refs` across files fail compilation closed.
