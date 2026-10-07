# Provider 02 — Certified Evidence Receipt (CER) Attestation Provider

> **Reference architecture note:** CAGE is an illustrative reference
> architecture. Providers are numbered and anonymized, and this integration has
> **no configured live endpoint** — every URL below is a placeholder. Adopters
> should treat this as an integration pattern to adapt, not a hosted service.
>
> **Naming note:** The vendor name for this integration is **NexArt**. The
> package path `provider_02` is retained for import stability across branches
> and test fixtures.

| Property | Value |
|---|---|
| Protocol | Vendor-specific attestation surface — **not** `NormativeProvider`, and **not** a subclass of the abstract [`AttestationProvider`](../../gateway/governance/attestation_provider.py:36) |
| Integration style | Out-of-band attestation; no per-transaction hot-path call |
| Classes | `Provider02AttestationProvider` ([`provider.py`](provider.py:137)), `Provider02Client` and `Provider02AttestationCallback` ([`adapter.py`](adapter.py:408)) |
| Status | HTTP clients implemented; no endpoint configured |
| Factory names | `provider_02`, alias `p02` (resolvable through `get_normative_provider()`, but it does not satisfy the `NormativeProvider` method set) |
| Conformance suite | Registered in `ATTESTATION_PROVIDERS`; covered by `test_attestation_providers_exist` ([`tests/test_normative_provider_conformance.py`](../../../tests/test_normative_provider_conformance.py:49)) |

## Verdict vocabulary

**None.** This provider does not emit a verdict and never produces a
`ValidationResult`. It certifies and verifies evidence rather than gating an
action, so there is no `admitted` mapping and nothing that can park in the
`DeferQueue`.

The nearest thing to an outcome is `CERVerification.valid` (a plain `bool`) plus
an optional `error` string ([`provider.py`](provider.py:100)).

## Two components

**1. `Provider02AttestationProvider`** — CER lifecycle.

| Method | Endpoint | Purpose |
|---|---|---|
| `attest_bundle()` | `POST {base}/api/attest` | Seal a completed bundle into a `cer.governed.execution.v1` CER, attest it, and verify both Ed25519 receipt signatures against the `kid`-resolved manifest key ([`governed_cer.py`](governed_cer.py)). Returns an `AttestationVerdict` |
| `certify_decision()` | `POST {base}/certifyDecision` | Submit a governance decision, receive a `CERReceipt`. **Route returns 404 on the live node (2026-10-06)** |
| `verify_cer()` | *(local)* → falls back to `GET {base}/verify/{hash}` | Verify against the cached JWK set; remote only when the cache is empty. **Remote route returns 404 on the live node** |

JWKs are synced out-of-band by a background asyncio task
([`_jwk_sync_loop()`](provider.py:408)) on a 24h default TTL with `ETag`/`304`
handling, so hot-path verification makes no network call.

> **Implementation note, verified in code:** [`_verify_local()`](provider.py:274)
> is **not** a complete Ed25519 verification. It confirms the JWK cache is
> populated and that the certificate hash is 64 hex characters, then returns
> `valid=True`. The full signature check is marked as pending finalization of
> the API contract. Adopters must not read a `valid=True` from this path as
> cryptographic proof.

**2. `Provider02AttestationCallback`** — a LangGraph callback handler that
snapshots `AgentState` at governance-significant node boundaries
(`nemo_guardrail`, `evaluator`, `safety_check`, `governed_trader`, `explainer`,
`nemo_output_rail`), deep-copying to survive destructive in-place loop mutation,
and assembles an `AttestationBundle` DAG at graph completion.

**State commitments.** Each step's `stateHash` is a *producer commitment*
(NexArt preserves and certificate-binds it but never recomputes it), so CAGE
retains the preimage. The callback is constructed with a `committer`
([`StateCommitter`](../../gateway/governance/seams/state_commitment.py)) and
stages a JSON-native snapshot per step. The async
[`seal()`](adapter.py:637) forwards each snapshot, in order, to the gateway's
`POST /governance/state-commitments` endpoint (via
`GatewayClient.commit_state`; caller authenticated by Linkerd mTLS
`l5d-client-id`). The gateway PII-sanitizes, JCS-canonicalizes (RFC 8785) and
SHA-256-hashes the snapshot once, appends a `STATE_COMMITMENT` event to the
evidence stream (the compliance-bridge custodian writes it to WORM storage with
`x-data-classification: internal-pii-sanitized`), and returns the `stateHash`.
Every step also carries `stateHashAlg: sha256`,
`stateHashCanon: RFC8785-JCS` and
`stateHashScope: agentstate-pii-sanitized/v1` metadata.
[`get_bundle()`](adapter.py:720) raises until the callback is sealed, so a
failed gateway commit means no step and no bundle (fail-closed).
[`submit_attested_bundle()`](adapter.py) (seal → attest → verify) is the single
submit path; it raises `Provider02Error(code="ATTESTATION_REJECTED")` unless
CAGE verified the node's receipt. Topology is omitted by default because the
node currently rejects cyclic topologies (see
[`HITL_INTEROP_STATUS.md`](../../../docs/partners/provider_02/nexart/HITL_INTEROP_STATUS.md)). The advisor holds no cold store and no Google Cloud identity.

`parentStepIds` records **executed** parents only: the callback tracks the
executed predecessor of each node event, including unrecorded nodes, and
contracts those executed edges back to the nearest recorded step. Each executed
edge must be a `GraphTopology.parent_edges` candidate. Otherwise
`LineageError` is raised (fail-closed). Node events are assumed to arrive
sequentially, so callers declare genuine parallel fan-in with
`on_chain_end(..., executed_predecessors=[...])`. `handle_hitl_interrupt()`
records `hitl_interrupt` as an ordinary executed node.

Terminal paths classified: `happy_path`, `nemo_block`, `cbf_block`,
`loop_breaker`, `unknown`.

## Error semantics

Two different conventions coexist in this package — worth knowing before you
wire it up:

| Component | On HTTP/transport failure |
|---|---|
| `Provider02AttestationProvider` ([`provider.py`](provider.py:252)) | Returns a dataclass with `error` populated (`CERReceipt(error=...)`, `CERVerification(valid=False, ...)`) |
| `Provider02Client` ([`adapter.py`](adapter.py:776)) | **Raises** `Provider02Error` with `code="ENDPOINT_ERROR"` |

## Wire contract change (breaking)

The request and response *shapes* sent to NexArt are unchanged, but:

- `stateHash` values differ from earlier builds: the snapshot is now
  PII-sanitized before RFC 8785 JCS canonicalization, and the hash is computed
  by the gateway (`StateCommitmentService`), not by the adapter. The former
  adapter-local `_hash_state()` was removed.
- Step `metadata` gains the three additive `stateHash*` method keys above.
- `Provider02AttestationCallback(topology, *, committer, thread_id="")` now
  requires a `committer`, and `get_bundle()` requires a prior `await seal()`.

## HITL interop

The HITL approval path (`safety_check` → `hitl_interrupt` → `governed_trader`) is
checked hermetically by
[`test_hitl_bundle_conformance.py`](../../../tests/integrations/provider_02/test_hitl_bundle_conformance.py)
and over the wire by `test_tc06_hitl_approval` / `test_tc_err_04_malformed_hitl_state_hash`
in [`test_staging_e2e.py`](../../../tests/integrations/provider_02/test_staging_e2e.py).
For partner versions and live-run status, see
[`HITL_INTEROP_STATUS.md`](../../../docs/partners/provider_02/nexart/HITL_INTEROP_STATUS.md).

## Configuration

Placeholder endpoints only. `PROVIDER_02_API_ENDPOINT`,
`PROVIDER_02_API_KEY_SECRET` / `PROVIDER_02_API_KEY`,
`PROVIDER_02_JWK_ENDPOINT`, `PROVIDER_02_JWK_CACHE_TTL_HOURS`,
`PROVIDER_02_TIMEOUT_SECONDS`, `PROVIDER_02_ATTESTATION_ENABLED` (default
`false`).

Secrets belong in `terraform.auto.tfvars` and reach pods via `secretKeyRef` —
never as literal values in committed files.
