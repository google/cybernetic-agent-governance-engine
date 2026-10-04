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

## Partner root cause (0.4.0 → 0.4.1)

The partner confirmed the 0.4.0 rejection was in their SDK, not malformed CAGE output.

- SDK 0.4.0 required `governed_trader.parentStepIds` to contain **every**
  `parentEdges` candidate (`safety_check` and `hitl_interrupt`). It rejected the
  valid HITL bundle, whose only actual parent is `hitl_interrupt`, with
  `MISSING_CONTRACTED_PARENT`.
- SDK 0.4.1 / Node 0.29.1 accept `parentStepIds` as a subset of the legal
  candidates. They still fail closed on illegal, unknown or stale parent
  references.
- No schema change was needed. The spec ([`NATIVE_SCHEMA_SPEC.md`](NATIVE_SCHEMA_SPEC.md) §2.4, §4.1)
  and the schema descriptions now say that `parentEdges` holds the *possible*
  relationships and `parentStepIds` the *actual* ones.
- The partner reports that the complete current CAGE HITL artifact passed their
  production validation unchanged.

### `stateHash` trust model

The partner keeps `stateHash` and binds it into the certificate as a
**producer-supplied commitment**. They do **not** recompute it from the preimage.
Independent verification of the commitment therefore depends on CAGE keeping
the canonical snapshot (the preimage). See the open items below.

## Open items

- **Actual vs. static parentage (CAGE emission).** Ancestor contraction in
  `_build_parent_step_ids()` resolves parents from static `parentEdges`, not from
  the edges actually traversed. On the HITL path, `explainer` lists
  `governed_trader`, `evaluator` and `safety_check`, and `nemo_output_rail` lists
  `nemo_guardrail` through `data_analyst`, which never ran. This is valid under
  the partner's subset rule, but it violates the clarified §4.1 rules 2–4. Fix:
  record only executed edges, then re-run the live staging cases.
- **`stateHash` preimage retention.** The adapter builds the canonical snapshot,
  hashes it and discards it. Because the partner doesn't recompute the hash, no
  party can verify the commitment today. Fix: keep the canonical snapshot in
  tamper-evident evidence storage, keyed by `stateHash`, and add a test that
  recomputes the hash from it.
