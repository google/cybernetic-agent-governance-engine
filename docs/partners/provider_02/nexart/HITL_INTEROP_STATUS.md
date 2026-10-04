# NexArt HITL Interoperability Status

Status record for the HITL approval-path interop between CAGE's Provider 02
adapter ([`adapter.py`](../../../../src/integrations/provider_02/adapter.py)) and
NexArt's governed-execution SDK and Node.

## Agreed invariants

The partner rejected the HITL bundles fail-closed on three counts. CAGE now emits:

| # | Invariant | CAGE implementation |
|---|---|---|
| 1 | `hitl_interrupt.stateHash` is SHA-256 hex (`^[a-f0-9]{64}$`) over the RFC 8785 JCS snapshot | `_hash_state()` in [`adapter.py`](../../../../src/integrations/provider_02/adapter.py) |
| 2 | `hitl_interrupt` is declared in `GraphTopology.nodes` and `attestation_nodes` | [`graph_topology.py`](../../../../src/cage_finance/graph_topology.py) |
| 3 | Lineage: `safety_check` → `hitl_interrupt` → `governed_trader`, and `governed_trader.parentStepIds == [hitl_interrupt.stepId]` | `_build_parent_step_ids()` / `handle_hitl_interrupt()` in [`adapter.py`](../../../../src/integrations/provider_02/adapter.py) |

The invariants are encoded once in
[`hitl_bundle.py`](../../../../tests/integrations/provider_02/hitl_bundle.py)
(`hitl_invariant_violations()`). That module also generates the partner fixture
[`06_hitl_approval.json`](../../../../tests/fixtures/provider_02_native/06_hitl_approval.json).

## Verification matrix

| Check | Kind | Result |
|---|---|---|
| [`test_hitl_bundle_conformance.py`](../../../../tests/integrations/provider_02/test_hitl_bundle_conformance.py): schema + invariants, runtime bundle and fixture | Hermetic (`unit`, `local`) | Pass (2026-10-04) |
| `test_tc06_hitl_approval` in [`test_staging_e2e.py`](../../../../tests/integrations/provider_02/test_staging_e2e.py) | Over the wire (`live_external`) | **Pending.** Not yet run from CAGE against Node 0.29.1 |
| `test_tc_err_04_malformed_hitl_state_hash` in [`test_staging_e2e.py`](../../../../tests/integrations/provider_02/test_staging_e2e.py) | Over the wire (`live_external`) | **Pending** |
| Partner-side re-run against CAGE `main` | Partner-reported | Pass, as reported by the partner on SDK 0.4.1 / Node 0.29.1 |

> [!IMPORTANT]
> Under the Over-the-Wire Conformance Mandate (AGENTS.md), only the
> `live_external` rows count as CAGE-side verification. The partner-reported pass
> and the hermetic suite are not a substitute.

Run the live cases with `PROVIDER_02_API_ENDPOINT` (and, if needed,
`PROVIDER_02_API_KEY_SECRET` and the mTLS variables) pointed at the partner staging Node:

```bash
uv run pytest tests/integrations/provider_02/test_staging_e2e.py -v --no-cov -p no:langsmith -n0
```

## Tested partner versions

| Partner component | Version | Verified by | Date |
|---|---|---|---|
| `@nexart/governed-execution` SDK | 0.4.1 | Partner only | Partner report, 2026-09-18 |
| NexArt Node | 0.29.1 | Partner only | Partner report, 2026-09-18 |

Change the "Verified by" column only after a CAGE over-the-wire run has passed.

## Open items

- **Partner-side compatibility fixes in 0.4.1 / 0.29.1.** The partner described
  them as minor and on their side, but did not list them. Ask for the list. If any
  of them reflects how CAGE emits bundles, update the vendored schemas in
  [`config/partners/provider_02/schemas`](../../../../config/partners/provider_02/schemas)
  and [`NATIVE_SCHEMA_SPEC.md`](NATIVE_SCHEMA_SPEC.md).
- **Parents on edges that weren't taken.** Ancestor contraction resolves parents
  from static topology edges, not from the edges actually traversed. On the HITL
  path, `explainer` therefore lists `governed_trader`, `evaluator` and
  `safety_check` as parents, and `nemo_output_rail` lists `nemo_guardrail` through
  `data_analyst`, which never ran. The partner accepts this today, and it doesn't
  affect the three agreed invariants. It is still weaker lineage than the strictly
  causal edge agreed for `governed_trader`.
