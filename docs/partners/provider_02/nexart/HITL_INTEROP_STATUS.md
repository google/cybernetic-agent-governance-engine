# NexArt HITL Interoperability Status

Status record for the HITL approval-path interop between CAGE's Provider 02
adapter ([`adapter.py`](../../../../src/integrations/provider_02/adapter.py)) and
NexArt's governed-execution SDK and Node.

## Agreed invariants

The partner rejected the HITL bundles fail-closed on three counts. CAGE now emits
the following (invariant 4 implements the clarified spec §4.1 rules 2–4):

| # | Invariant | CAGE implementation |
|---|---|---|
| 1 | `hitl_interrupt.stateHash` is SHA-256 hex (`^[a-f0-9]{64}$`) over the RFC 8785 JCS bytes of the PII-sanitized snapshot, and every step carries `stateHashAlg="sha256"`, `stateHashCanon="RFC8785-JCS"`, `stateHashScope="agentstate-pii-sanitized/v1"` in `metadata` | Gateway `StateCommitmentService` in [`state_commitment.py`](../../../../src/gateway/governance/evidence/state_commitment.py); `Provider02AttestationCallback.seal()` in [`adapter.py`](../../../../src/integrations/provider_02/adapter.py) |
| 2 | `hitl_interrupt` is declared in `GraphTopology.nodes` and `attestation_nodes` | [`graph_topology.py`](../../../../src/cage_finance/graph_topology.py) |
| 3 | Lineage: `safety_check` → `hitl_interrupt` → `governed_trader`, and `governed_trader.parentStepIds == [hitl_interrupt.stepId]` | `_resolve_executed_parents()` / `handle_hitl_interrupt()` in [`adapter.py`](../../../../src/integrations/provider_02/adapter.py) |
| 4 | Actual parents only: every `parentStepIds` entry is an executed edge that is legal under `parentEdges` (`explainer == [governed_trader]`, `nemo_output_rail == [explainer]`) | `_resolve_executed_parents()` in [`adapter.py`](../../../../src/integrations/provider_02/adapter.py); illegal edges raise `LineageError` |

The invariants are encoded once in
[`hitl_bundle.py`](../../../../tests/integrations/provider_02/hitl_bundle.py)
(`hitl_invariant_violations()`). That module also generates the partner fixture
[`06_hitl_approval.json`](../../../../tests/fixtures/provider_02_native/06_hitl_approval.json).

## Verification matrix

| Check | Kind | Result |
|---|---|---|
| [`test_hitl_bundle_conformance.py`](../../../../tests/integrations/provider_02/test_hitl_bundle_conformance.py): schema + invariants, runtime bundle and fixture | Hermetic (`unit`, `local`) | Pass (2026-10-04) |
| `test_tc06_hitl_approval[runtime,fixture]` in [`test_staging_e2e.py`](../../../../tests/integrations/provider_02/test_staging_e2e.py) | Over the wire (`live_external`, `POST /api/attest`) | **Pass (2026-10-06 / 2026-10-10)** against Node v0.30.0 & v0.30.1 (`nexart-node-prod-1`). `certificateIntegrity`, `cageSchemaValidity`, `causalGraphValidity`, `resourceSafety` all `valid`; both receipt signatures verified by CAGE against manifest key `k1` |
| `test_tc07_hitl_with_topology` (cyclic `FINANCIAL_ADVISOR_TOPOLOGY` supplied) | Over the wire (`live_external`, `POST /api/attest`) | **Pass (2026-10-10)** against Node v0.30.1 / SDK 0.4.2 (`nexart-node-prod-1`). `topologyValidation: "valid"`, both Ed25519 receipt and verification-envelope signatures verified by CAGE against manifest key `k1` |
| `test_tc_err_04_malformed_hitl_state_hash` in [`test_staging_e2e.py`](../../../../tests/integrations/provider_02/test_staging_e2e.py) | Over the wire (`live_external`, `POST /api/attest` & `POST /v1/cer/verify`) | **Pass (2026-10-06 / 2026-10-10):** rejected `SCHEMA_ERROR` (`stateHash: lowercase 64-character hexadecimal required`) |
| `test_tc_err_01_invalid_parent` (dangling parent) | Over the wire (`live_external`, `POST /api/attest` & `POST /v1/cer/verify`) | **Pass (2026-10-06 / 2026-10-10):** rejected `CAUSAL_ERROR` (`missing parent`) |
| `test_verify_tc07_hitl_with_topology[runtime,fixture]` (cyclic `FINANCIAL_ADVISOR_TOPOLOGY` supplied) | Over the wire (`live_external`, `POST /v1/cer/verify`) | **Pass (2026-10-10)** against Node v0.30.1 / SDK 0.4.2 (`nexart-node-prod-1`). `topologyValidation: "valid"`, `computedCertificateHash == certificateHash` |
| `test_verify_tc08_multi_iteration_loop_with_topology` (two-iteration `execution_analyst` ↔ `evaluator` refinement loop with cyclic topology) | Over the wire (`live_external`, `POST /v1/cer/verify`) | **Pass (2026-10-10)** against Node v0.30.1 / SDK 0.4.2 (`topologyValidation: "valid"`) |
| `test_verify_err_forbidden_executed_edge` (illegal edge under `FINANCIAL_ADVISOR_TOPOLOGY`) | Over the wire (`live_external`, `POST /v1/cer/verify`) | **Pass (2026-10-10):** rejected `TOPOLOGY_ERROR` (`ILLEGAL_EXECUTED_EDGE`, `topologyValidation: "invalid"`) |
| TC-01 to TC-05, TC-ERR-02, TC-ERR-03 | Over the wire (`live_external`, `POST /api/attest`) | **Pass (2026-10-06 / 2026-10-10)** |
| Partner-side re-run against CAGE `main` | Partner-reported | Pass, as reported by the partner on SDK 0.4.2 / Node 0.30.1 |

> [!IMPORTANT]
> Under the Over-the-Wire Conformance Mandate (AGENTS.md), only the
> `live_external` rows count as CAGE-side verification. The partner-reported pass
> and the hermetic suite are not a substitute.

Run the live cases with `PROVIDER_02_API_ENDPOINT` (node base URL) and, for
authenticated `POST /api/attest` runs, `PROVIDER_02_API_KEY_SECRET` (and, if
needed, the mTLS variables) set:

```bash
uv run pytest tests/integrations/provider_02/test_staging_e2e.py --run-live-external -v --no-cov -p no:langsmith -n0
```

### Wire protocol (verified 2026-10-06 and 2026-10-10)

The node does not expose `/v1/governance/bundles`, `/registerProjectBundle`,
`/certifyDecision` or `/verify/{hash}` (all 404). The live contract is:

- `POST /api/attest`, `Authorization: Bearer <key>`, body = a
  `cer.governed.execution.v1` CER (version `0.1`, profile `cage-governance-v1`)
  whose `evidence.bundle` is the CAGE `AttestationBundle` and `evidence.topology`
  is the wire `GraphTopology`. Step-level CERs are rejected
  (`UNSUPPORTED_BUNDLE_TYPE`).
- `POST /v1/cer/verify`, body = `{"bundle": <cer>}` — stateless, non-persisting
  verification of a caller-sealed CER. Runs the full governed-execution check
  suite (`certificateIntegrity`, `cageSchemaValidity`, `causalGraphValidity`,
  `topologyValidation`, `resourceSafety`) and returns `computedCertificateHash`
  without persisting a record on the node.
- `GET /v1/resolve/cer/:certificateHash` — resolves a persisted public CER.
- `certificateHash` = `sha256:` + SHA-256 over the RFC 8785 JCS bytes of the CER
  without `certificateHash`. CAGE's JCS and the node agree byte-for-byte.
- `createdAt` must be deterministic per `bundleId` (CAGE uses `completedAt`): a
  resubmission with different content returns `EXECUTION_MUTATION_DETECTED`.
- On `POST /api/attest`, the response carries `signature` (Ed25519 over
  `JCS(receipt)`) and `verificationEnvelopeSignature` (Ed25519 over the
  `signedFields` projection of the CER and envelope attestation). The key is
  resolved by `kid` from `/.well-known/nexart-node.json`, never from the
  response.

CAGE side: [`governed_cer.py`](../../../../src/integrations/provider_02/governed_cer.py)
(`seal_governed_execution()`, `verify_attestation()`, `verify_governed_cer()`)
and `Provider02AttestationProvider.attest_bundle()` / `verify_bundle()` in
[`provider.py`](../../../../src/integrations/provider_02/provider.py).

## Tested partner versions

| Partner component | Version | Verified by | Date |
|---|---|---|---|
| `@nexart/governed-execution` SDK | 0.4.1 | Partner only | Partner report, 2026-09-18 |
| NexArt Node | 0.29.1 | Partner only | Partner report, 2026-09-18 |
| NexArt Attestation Node (`nexart-node-prod-1`) | v0.30.0 | CAGE (over the wire) | 2026-10-06 |
| NexArt Attestation Node (`nexart-node-prod-1`) + `@nexart/governed-execution` SDK | v0.30.1 / 0.4.2 | CAGE (over the wire) | 2026-10-10 |

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
the canonical snapshot (the preimage), which it now does:

- The adapter no longer hashes anything. `seal()` sends each step's snapshot to
  the gateway (`POST /governance/state-commitments`, Linkerd mTLS workload
  identity), which PII-sanitizes it with the evidence-chain sanitizer,
  canonicalizes it once (RFC 8785), hashes it (SHA-256) and appends the
  sanitized preimage to the hash-chained evidence stream as a
  `STATE_COMMITMENT` record. The compliance bridge custodies that record into
  the WORM bucket under a KMS-signed batch attestation.
- A bundle cannot be obtained (`get_bundle()` raises) until every step has a
  gateway receipt, so a failed commitment emits no step and no bundle.
- Verification: `verify_state_commitment()` re-canonicalizes the record's
  `state` and compares SHA-256 with the step's `stateHash`; `linkageDigest`
  binds the record to the exact `bundleId` / `stepId`.
- The digest binds the **sanitized** state. Bundles without the
  `stateHashScope` key were hashed over raw state and cannot be recomputed from
  a sanitized preimage.

## Resolved items

- **Actual vs. static parentage (CAGE emission).** The adapter used to contract
  ancestors over static `parentEdges`, so on the HITL path `explainer` listed
  `governed_trader`, `evaluator` and `safety_check`, and `nemo_output_rail`
  reached `nemo_guardrail` through `data_analyst`, which never ran.
  `_resolve_executed_parents()` in
  [`adapter.py`](../../../../src/integrations/provider_02/adapter.py) now tracks
  the executed predecessor of every node event, including unrecorded nodes, and
  contracts only those executed edges back to the nearest recorded step. Each
  executed edge must be a `parentEdges` candidate; otherwise the adapter raises
  `LineageError` (fail-closed). `hitl_interrupt` is an ordinary executed node, so
  `governed_trader == [hitl_interrupt]` needs no special case. Invariant 4 in
  [`hitl_bundle.py`](../../../../tests/integrations/provider_02/hitl_bundle.py)
  checks this, and
  [`06_hitl_approval.json`](../../../../tests/fixtures/provider_02_native/06_hitl_approval.json)
  was regenerated. Partner impact: every emitted parent is still a legal
  candidate, so bundles stay valid under the SDK 0.4.1 / Node 0.29.1 subset rule.
  The bundles are smaller; they are not looser. Verified over the wire on
  2026-10-06 (`test_tc06_hitl_approval`, Node v0.30.0).

- **Cyclic topology accepted by Node v0.30.1 / SDK 0.4.2 (over the wire, 2026-10-10).**
  Node v0.30.0 rejected `FINANCIAL_ADVISOR_TOPOLOGY` with
  `TOPOLOGY_ERROR: "topology: cycle includes evaluator"` because of the bounded
  `execution_analyst` ↔ `evaluator` refinement loop. NexArt deployed Node v0.30.1
  with Governed Execution SDK 0.4.2, permitting static control-flow cycles in
  `evidence.topology` while requiring concrete `parentStepIds` executions to
  remain acyclic and legal under ancestor contraction. Verified over the wire on
  2026-10-10 via `POST /v1/cer/verify` (`test_verify_tc07_hitl_with_topology`
  for both runtime and `06_hitl_approval.json`,
  `test_verify_tc08_multi_iteration_loop_with_topology` for a two-iteration
  `execution_analyst` ↔ `evaluator` loop, and
  `test_verify_err_forbidden_executed_edge` confirming `TOPOLOGY_ERROR` /
  `ILLEGAL_EXECUTED_EDGE` on an illegal edge). `submit_attested_bundle()` in
  [`adapter.py`](../../../../src/integrations/provider_02/adapter.py) now
  defaults to `include_topology=True`.

- **Stateless verification route (`POST /v1/cer/verify`).** Partner confirmed
  `/certifyDecision` and `/verify/{hash}` are not Node HTTP endpoints; stateless
  non-persisting verification lives at `POST /v1/cer/verify`. Implemented in
  `Provider02AttestationProvider.verify_bundle()` and `verify_governed_cer()`,
  and wired into [`test_staging_e2e.py`](../../../../tests/integrations/provider_02/test_staging_e2e.py)
  and [`test_provider_02_live.py`](../../../../tests/integrations/provider_02/test_provider_02_live.py).

- **`stateHash` preimage retention (hermetic).** The sanitized preimage is
  retained in the evidence chain and the hash recomputes from it
  ([`test_state_commitment_adapter.py`](../../../../tests/integrations/provider_02/test_state_commitment_adapter.py),
  [`test_state_commitment_service.py`](../../../../tests/test_state_commitment_service.py)).
  Live verification is still pending: the WORM-path checks in
  [`test_state_commitment_worm_live.py`](../../../../tests/integrations/test_state_commitment_worm_live.py)
  have not yet been run against the staging bucket, and closure is tracked by
  POAM-2026-084 in [`POAM.md`](../../../POAM.md).

## Open items

- **Live WORM verification of state preimages.** Run
  `test_state_commitment_worm_live.py` against the locked staging bucket
  (`CAGE_LIVE_WORM_BUCKET`) and record the result here and in POAM-2026-084.
- **Production callback wiring.** `FINANCIAL_ADVISOR_TOPOLOGY` now declares
  `ftra_node`, `defer_node` and `approval_node`, but no server route drives
  `submit_attested_bundle()` yet.

