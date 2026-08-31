# Non-Formation Proof Specification — `GovernanceRefusalReceipt` v3

> **Reference Architecture Note:** This document describes an *illustrative extension pattern* for adopters in litigation-exposed sectors (e.g., defense contractors, disputed-transaction banking) who require cryptographic non-formation proofs replayable decades later. It is **not** a CAGE operational obligation and is **not implemented** in CAGE core. Adopters should adapt these patterns to their specific legal/regulatory requirements. For the immediate, implemented improvement derived from this analysis, see the `standing_at_refusal` hash-binding fix in [`contracts.py`](../../src/gateway/governance/contracts.py).

> **Document Type:** Architecture Design Document (design-only, no implementation)
> **Status:** Draft for review
> **Author context:** CAGE-SEC-009 / Terry Snyder burden-of-proof extension (Part 5)
> **Scope:** Extends the existing 5-part `RefusalReceipt` (schema v2) in
> [`contracts.py`](../../src/gateway/governance/contracts.py:52) to a formal
> **9-part non-formation proof** — a cryptographic artifact that proves a
> blocked action **never mathematically existed**, as distinct from an action
> that occurred and was later rolled back.

---

## 1. Framing: Non-Formation vs. Rollback

CAGE already implements **rollback** correctly — e.g.
[`ControlBarrierFunction.rollback_state()`](../../src/gateway/governance/cbf.py:1230)
compensates a committed Redis balance debit when a downstream tier fails
*after* the CBF commit succeeded (Saga pattern, §7.3 of the CAGE paper). That is
"X happened, then X was undone."

**Non-formation is a different, stronger claim.** It says: for actions blocked
*before* the point of no return (before `atomic_verify_and_commit()`, before
`routing_seal` issuance, before any external side-effect), there is no `t`
at which the consequence existed in any observable form — not even
transiently. The proof obligation is therefore not "we reversed it" but
"it was cryptographically impossible for it to have formed."

This maps directly onto CAGE's existing **No-Direct-Bind invariant**
(proved exhaustively in [`proof/model.py`](../../proof/model.py:42)):

```
NoDirectBind == (phase = "EXECUTED") => (resolvedAllow = TRUE)
```

Non-formation is the *contrapositive*, made evidentiary rather than purely
formal: `resolvedAllow = FALSE` implies `phase != "EXECUTED"`, and the
`GovernanceRefusalReceipt` is the signed, replayable witness that this
contrapositive held for one specific request, at one specific instant,
against one specific compiled rule-set.

This document defines the receipt schema, the components that already
supply each of Terry's 9 proof elements, the components that must be built,
and the cryptographic guarantees (JCS canonicalization, KMS signing, WORM
storage, rule-snapshot separation) that make the receipt independently
auditable ten years after issuance.

---

## 2. Existing Infrastructure Analysis

### 2.1 `contracts.py` — the current 5-part proof chain (schema v2)

[`RefusalReceipt`](../../src/gateway/governance/contracts.py:52) already
implements a **5-part causal chain** (schema v2, `__post_init__` at
[`contracts.py:83`](../../src/gateway/governance/contracts.py:83)):

| Terry (5-part, existing) | `RefusalReceipt` field |
|---|---|
| 1. Attempted movement | `action` + `attempted_params` |
| 2. Standing | `standing_snapshot` (per-tier `governing_state`) |
| 3. Governing condition | `control_id` + `violated_rule` + `tier_failures[].rule_description` |
| 4. Protected consequence | `protected_consequence` |
| 5. Non-formation | `non_formation_proof` (currently a fixed string constant `"action_blocked_pre_commit"`) |

The receipt is SHA-256 hashed over its **JCS-canonicalized** payload
(`jcs_canonicalize_plan()`, imported at
[`contracts.py:114`](../../src/gateway/governance/contracts.py:114)), giving
it `proof_hash` — but the receipt is **never KMS-signed**, never persisted to
WORM storage, and `non_formation_proof` is a **string label**, not a
cryptographic proof object. This is the exact gap Part 5 must close: turn
`non_formation_proof: str` into a verifiable cryptographic sub-claim with its
own evidence.

[`GovernanceTierFailure`](../../src/gateway/governance/contracts.py:28) is
the structured per-tier failure record — one is emitted per failing tier
(CBF, OPA, NEURAL_CONFIDENCE, FISCAL, FTRA, etc.) inside
[`symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py:1102)
(`_run_checks()`), and the first failing tier's record seeds the receipt's
`control_id` / `standing_snapshot` / `protected_consequence` at
[`symbolic_governor.py:1820-1849`](../../src/gateway/governance/symbolic_governor.py:1820).

### 2.2 `decisions.py` — canonical decision vocabulary

[`GovernanceDecision`](../../src/gateway/governance/decisions.py:81) is the
five-state enum (`ALLOW/DENY/PAUSE/NARROW/REQUIRE_APPROVAL/DEFER`) that must
label the receipt's outcome. Only `DENY` (and, per §7, `PAUSE` when it times
out to auto-deny) triggers `GovernanceRefusalReceipt` issuance. `DEFER` and
`REQUIRE_APPROVAL` are explicitly **not** non-formation claims — they are
open questions about *whether* the action forms, not proofs that it did not;
Part 5 receipts apply only to terminal `DENY` outcomes.

### 2.3 `provenance_chain.py` — hash-chain precedent (link-list pattern)

[`ProvenanceRecord`](../../src/gateway/governance/provenance_chain.py:98)
already demonstrates the hash-chain-of-custody pattern the new receipt reuses:
`parent_hash` links each node to its predecessor,
[`compute_hash()`](../../src/gateway/governance/provenance_chain.py:146) uses
JCS canonicalization, and
[`verify_chain_integrity()`](../../src/gateway/governance/provenance_chain.py:227)
walks the chain re-deriving each `parent_hash`. The new receipt's **rule
snapshot chain** (§6.4) follows this exact pattern rather than inventing a
new one.

### 2.4 `jcs_canonicalizer.py` — deterministic byte representation

[`jcs_canonicalize_plan()`](../../src/gateway/governance/jcs_canonicalizer.py:24)
wraps an RFC 8785 JCS implementation and is the **single canonicalization
primitive** the receipt must use for every hashed/signed sub-structure. RFC
8785 fixes: key ordering (lexicographic), number formatting (no
language-specific float drift), and string escaping — guaranteeing that a
Python-issued receipt and a Go/Rust/Java external verifier compute the
**same digest** from the **same JSON document**, indefinitely. This is the
foundation of "same-condition immutability" (§7.1): without JCS, two
semantically-identical replay computations could hash differently purely
due to platform float/locale formatting differences.

### 2.5 `kms_signer.py` — non-repudiation via asymmetric HSM signing

[`KMSGovernanceSigner`](../../src/gateway/governance/kms_signer.py:391)
provides multi-cloud (GCP/AWS/Azure) asymmetric signing with:
- [`sign_precomputed_digest()`](../../src/gateway/governance/kms_signer.py:624) —
  signs a pre-computed digest directly (used by
  `GovernanceEnvelope.compute_digest()` today); this is the method the new
  receipt's signing step reuses.
- [`verify()`](../../src/gateway/governance/kms_signer.py:762) — independent
  signature verification against the loaded public key PEM, with a **replay
  staleness check** (`MAX_KMS_PAYLOAD_AGE_SECONDS`, default 300s) that is
  **not applicable** to refusal receipts (a receipt must remain verifiable
  indefinitely, not just for 5 minutes — see §7.1 for how the receipt design
  avoids this staleness gate).
- Fail-closed guarantee: [`_kms_sign()`](../../src/gateway/governance/kms_signer.py:654)
  has **no HMAC fallback** in production — `assert_kms_active_in_production()`
  ([`kms_signer.py:851`](../../src/gateway/governance/kms_signer.py:851))
  raises at startup if KMS is not active. This is the exact non-repudiation
  guarantee Terry's proof element 7 (Evidence/Receipt) requires: a receipt
  signed by CAGE's KMS key cannot have been forged by CAGE's own application
  code, because the private key material never leaves the HSM.

### 2.6 `jwks.py` — public key distribution for external verifiers

[`JWKSet`](../../src/gateway/governance/jwks.py:168) exposes CAGE's rotating
public keys via a standard JWKS document (`/jwks` endpoint), with `kid`-based
key lookup ([`get_verification_key_for_jwt()`](../../src/gateway/governance/jwks.py:443))
supporting **key rotation with grace periods**
([`rotate_key()`](../../src/gateway/governance/jwks.py:292)). This is the
mechanism an external auditor (regulator, court, adopter) uses to fetch the
verification key for a receipt signed years ago — provided the historical
`kid` is still resolvable (§7.1 requires retaining retired public keys
indefinitely for receipt verification, distinct from the JWT-seal grace
period which is intentionally short).

### 2.7 `constants.py` — the rule-snapshot precedent

[`ControlRegistry`](../../src/gateway/governance/constants.py:197) already
computes and caches an `active_hash` — a SHA-256 over the canonicalized
active regional compliance baseline JSON
([`_load_registry()`](../../src/gateway/governance/constants.py:276), lines
322-331). This is the **exact precedent** for the receipt's `rule_snapshot`
field (§6.4): a content-addressed hash of the compiled rule-set in effect at
refusal time, decoupled from the receipt's own signature so that the rule
can be independently versioned, audited, and diffed without invalidating
past receipts (§7.2).

### 2.8 `governance_envelope.py` — the attestation-embedding precedent

[`GovernanceEnvelope`](../../src/gateway/governance/governance_envelope.py:231)
already demonstrates every architectural pattern the new receipt needs:
JCS-canonicalized digest ([`compute_digest()`](../../src/gateway/governance/governance_envelope.py:277)),
KMS-signed via `sign_precomputed_digest()`, and an
`external_attestations[]` array
([`ExternalAttestation`](../../src/gateway/governance/governance_envelope.py:198))
for embedding third-party proof objects that are covered by the *same*
signature as the rest of the envelope. **Design decision (§5):** rather than
inventing a parallel envelope, `GovernanceRefusalReceipt` is emitted as a new
`EnvelopeType.GOVERNANCE_DECISION` envelope payload (or a sibling
`EnvelopeType.REFUSAL_RECEIPT`), reusing the builder, the signature block,
and the verification code path unchanged.

### 2.9 `routing_seal.py` — the affirmative counterpart (No-Bind evidence)

[`verify_and_consume_seal()`](../../src/gateway/governance/routing_seal.py:620)
and [`verify_seal()`](../../src/gateway/governance/routing_seal.py:435) prove
the **positive** claim ("this seal was issued, is unexpired, matches this
action_hash, and has not been replayed"). The non-formation receipt needs the
**negative mirror**: cryptographic proof that **no seal was ever issued** for
the attempted action/params combination. Because seal issuance
([`generate_seal_with_evidence()`](../../src/gateway/governance/symbolic_governor.py:1865))
only happens after `_run_checks()` returns zero violations
([`symbolic_governor.py:1857-1867`](../../src/gateway/governance/symbolic_governor.py:1857)),
the **absence of a seal record** for a given `action_hash` + `thread_id` in
the evidence stream is itself the "no-bind" evidence (§6.5, §4 proof element
4).

### 2.10 `cbf.py` — the atomicity boundary the receipt must reference

[`atomic_verify_and_commit()`](../../src/gateway/governance/cbf.py:1230)
collapses the CBF safety check and the Redis balance debit into a single Lua
script — eliminating the TOCTOU window between "checked safe" and
"committed". For non-formation to hold, the receipt must record which side
of this atomic boundary the refusal occurred on:
- **Pre-commit refusal** (the common case — Tier 1-6 violation before Phase 2
  mutation): non-formation is total; nothing was ever written.
- **Post-commit-but-pre-seal refusal** (rare — e.g. fiscal guard fails after
  CBF commit succeeded): this is a **rollback** case, not non-formation, and
  must be labeled as such (see `formation_boundary` field, §6.3) — a Terry
  Snyder receipt issued here documents that a compensating transaction
  restored state, which is a different (weaker but still valid) evidentiary
  claim than "never formed."

### 2.11 OSCAL / `compliance/oscal/` — external artifact conventions

The existing OSCAL artifacts
([`component-definition.yaml`](../../compliance/oscal/component-definition.yaml),
[`sp800-53-component-definition.yaml`](../../compliance/oscal/sp800-53-component-definition.yaml))
establish the pattern of mapping internal control IDs to external
machine-readable compliance schemas consumable by Lula and `oscal-cli`. The
new receipt's `control_id` and `tier_failures[].control_id` fields are
designed to resolve through the same
[`ControlRegistry.get_mapping()`](../../src/gateway/governance/constants.py:356)
lookup used elsewhere, so a receipt can be cross-referenced to its OSCAL
control entry (e.g. `CTRL_CBF_002` → SP 800-53 `SC-4`) without a new mapping
table.

### 2.12 Third-party schema precedents (`local/integrations/singh/`)

Two externally-authored schemas already sketch adjacent concepts and are
useful prior art (not dependencies):
[`integrity-receipt.schema.json`](../../local/integrations/singh/integrity-receipt.schema.json)
defines a signed receipt with `policyDigest` + `envelopeDigest` +
`verification.status` (`PASS/REVIEW/BLOCKED`) bound by an Ed25519
`signature`, and
[`integrity-envelope.schema.json`](../../local/integrations/singh/integrity-envelope.schema.json)
defines an immutable `decisionRegistryDigest` separating policy decisions
from response content. The `GovernanceRefusalReceipt` design (§6) borrows the
**digest-separation principle** (policy/rule digest kept distinct from the
per-event digest) from this precedent while remaining natively integrated
with CAGE's JCS/KMS/JWKS stack rather than adopting a parallel Ed25519-only
scheme.

---

## 3. Terry's 9-Part Burden of Proof — Mapped to CAGE

This section is the traceability spine of the document: every design choice
in §5-§8 is justified by exactly one row below.

| # | Proof Element | Question Answered | Primary CAGE Mechanism (existing) | Gap Closed By (new, §5) |
|---|---|---|---|---|
| 1 | **Intent (Movement)** | What action did the agent attempt? | `attempted_params` field, already captured in `RefusalReceipt` v2 ([`symbolic_governor.py:1836`](../../src/gateway/governance/symbolic_governor.py:1836)) | `intent` sub-object with full pre-normalization params + `action_hash` (JCS) |
| 2 | **Baseline (Present standing)** | By what authority did it claim permission? | `standing_snapshot` from `GovernanceTierFailure.governing_state` ([`contracts.py:48`](../../src/gateway/governance/contracts.py:48)) + `agent_catalog.rego` SPIFFE scope check | `baseline` sub-object: agent identity, claimed scope, `policy_version` hash at evaluation time |
| 3 | **Failure (Lost standing)** | Which specific rule/threshold caused refusal? | `control_id` + `violated_rule` + `tier_failures[]` ([`contracts.py:69-81`](../../src/gateway/governance/contracts.py:69)) | `failure` sub-object: full `tier_failures[]` array (not just first), each resolved through `ControlRegistry.get_mapping()` to external citation |
| 4 | **Block (No-bind)** | Cryptographic proof governance seal was rejected/never issued | Implicit: `govern()` raises `GovernanceError` **before** `generate_seal_with_evidence()` is reached ([`symbolic_governor.py:1853` vs `:1865`](../../src/gateway/governance/symbolic_governor.py:1853)) | Explicit `no_bind_proof` sub-object: signed attestation that no `routing_seal` record exists for this `action_hash`+`thread_id` in the evidence stream (§6.5) |
| 5 | **Protection (Unformed consequence)** | Proof external API/consequence was never touched | `protected_consequence` string field (human-readable only) ([`contracts.py:79`](../../src/gateway/governance/contracts.py:79)) | `protection_proof` sub-object: `formation_boundary` enum (§6.3) + reference to CBF/actuator state showing no mutation occurred, or rollback evidence if it did (Saga case) |
| 6 | **Containment (Route closure)** | Proof no backdoors or alternate routes existed | `proof/model.py` BFS exhaustive state-space proof (all reachable states satisfy `NoDirectBind`) — a **static, system-wide** proof, not per-transaction | `containment_attestation` sub-object: per-receipt reference to the pinned proof artifact hash (`proof/model.py` output digest) + confirmation the deployed commit matches the proved commit (§6.6) |
| 7 | **Evidence (Receipt)** | Immutable signed hash proving all above | `proof_hash` (SHA-256 over JCS bytes) — **computed but never KMS-signed or persisted to WORM** ([`contracts.py:83-117`](../../src/gateway/governance/contracts.py:83)) | Full `GovernanceEnvelope`-wrapped, KMS-signed, WORM-persisted receipt (§5, §6) |
| 8 | **Same-condition immutability** | Receipt replays to same refusal in 10 years | JCS canonicalization guarantees deterministic bytes ([`jcs_canonicalizer.py`](../../src/gateway/governance/jcs_canonicalizer.py:24)); KMS public key retained via JWKS rotation history | Formal **replay procedure** (§7.1): re-run `_run_checks()` against the frozen `rule_snapshot` + `attempted_params` and assert identical `tier_failures[]` |
| 9 | **Changed-condition immutability** | Rule changes create new receipts, original untouched | `ControlRegistry.active_hash` changes on `reconfigure()` ([`constants.py:398`](../../src/gateway/governance/constants.py:398)), decoupled from any receipt already issued | `rule_snapshot` field frozen at issuance + separate `rule_lineage` chain (§6.4, §7.2) so old receipts are never mutated when policy changes |

---

## 4. Component Mapping Table — Existing vs. New

| Component | Status | Role in Non-Formation Proof |
|---|---|---|
| [`RefusalReceipt`](../../src/gateway/governance/contracts.py:52) (schema v2) | ✅ Existing | Base structure; becomes the `failure` + `intent` core of v3 (renamed/extended, not replaced) |
| [`GovernanceTierFailure`](../../src/gateway/governance/contracts.py:28) | ✅ Existing | Populates `failure.tier_failures[]` unchanged |
| [`jcs_canonicalize_plan()`](../../src/gateway/governance/jcs_canonicalizer.py:24) | ✅ Existing | Canonicalization primitive for every hashed sub-object |
| [`KMSGovernanceSigner.sign_precomputed_digest()`](../../src/gateway/governance/kms_signer.py:624) | ✅ Existing | Signing primitive — reused verbatim |
| [`JWKSet`](../../src/gateway/governance/jwks.py:168) / `/jwks` endpoint | ✅ Existing | Public-key distribution for external replay verification |
| [`GovernanceEnvelopeBuilder`](../../src/gateway/governance/governance_envelope.py:290) | ✅ Existing | Envelope wrapper — receipt becomes envelope `payload` |
| [`ControlRegistry.active_hash`](../../src/gateway/governance/constants.py:253) | ✅ Existing | Direct precedent for `rule_snapshot.rule_digest` |
| [`ProvenanceRecord`](../../src/gateway/governance/provenance_chain.py:98) hash-chain pattern | ✅ Existing (pattern reused) | Template for `rule_lineage` chain (§6.4) |
| `GovernanceDecision.DENY` ([`decisions.py:99`](../../src/gateway/governance/decisions.py:99)) | ✅ Existing | Trigger condition for receipt issuance |
| `evidence_stream.py` hash-chained Redis→GCS WORM pipeline | ✅ Existing (repurposed) | Persistence layer for `GovernanceRefusalReceipt` records (§6.7) |
| `proof/model.py` BFS state-space proof | ✅ Existing (referenced, not modified) | Source of the `containment_attestation.proof_artifact_digest` (§6.6) |
| `ControlRegistry.get_mapping()` | ✅ Existing | Resolves `control_id` → external citation for `failure.tier_failures[].external_citation` |
| **`GovernanceRefusalReceipt` v3 dataclass** | 🆕 New | The unified 9-field schema (§6) |
| **`no_bind_proof` sub-object + evidence-stream absence-check** | 🆕 New | Closes proof element 4 — needs a new query helper against `evidence_stream.py` (§6.5) |
| **`formation_boundary` enum + protection-proof binding** | 🆕 New | Closes proof element 5 — new enum + CBF-state reference (§6.3) |
| **`containment_attestation` sub-object** | 🆕 New | Closes proof element 6 — new field referencing pinned `proof/model.py` digest + deployed commit SHA (§6.6) |
| **`rule_snapshot` + `rule_lineage` chain** | 🆕 New | Closes proof element 9 — new chained structure mirroring `ProvenanceRecord` (§6.4) |
| **Receipt WORM persistence path** (`refusal-receipts/<date>/<receipt_id>.json`) | 🆕 New | Closes proof element 7 fully — extends existing GCS CMEK bucket convention from `provenance_chain.py`/`evidence_stream.py` docstrings |
| **Replay verification procedure/tool** | 🆕 New | Closes proof element 8 — a new `scripts/replay_refusal_receipt.py`-class utility (design only, §7.1) |
| **`GovernanceRefusalReceipt` OSCAL cross-reference emitter** | 🆕 New (optional) | Feeds `oscal_ssp_exporter.py`-style ingestion for regulator-facing evidence bundles |

---

## 5. Architectural Design Decisions

1. **Extend, don't replace `RefusalReceipt`.** `GovernanceRefusalReceipt` v3
   is a superset dataclass — every schema v2 field is preserved verbatim
   (backward-compatible consumers, e.g. `symbolic_governor.py`'s existing
   `raise GovernanceError(..., receipt=receipt)` call sites, continue to
   work). New fields are additive (`intent`, `baseline`, `no_bind_proof`,
   `protection_proof`, `containment_attestation`, `rule_snapshot`,
   `rule_lineage`, `envelope_signature`).

2. **Envelope-wrap, don't re-invent signing.** The receipt's JCS-canonical
   bytes become the `payload` of a `GovernanceEnvelope`
   (`EnvelopeType.GOVERNANCE_DECISION` or a new sibling
   `EnvelopeType.REFUSAL_RECEIPT`), so `GovernanceEnvelopeBuilder.build()`,
   `attach_signature()`, and `verify()` are reused unmodified. No new signing
   code path is introduced — this directly satisfies proof element 7 with
   zero new cryptographic surface area to audit.

3. **Decouple the rule snapshot from the receipt signature.** Per proof
   element 9, `rule_snapshot` records the `ControlRegistry.active_hash`
   value *at refusal time*, but is **not itself re-derived** on replay — it
   is a frozen historical fact, verified only by chain-of-custody (§6.4,
   §7.2), not by recomputing the current registry (which would have since
   changed). This is the critical design choice that makes changed-condition
   immutability possible: the receipt says "this is what the rule *was*,"
   never "this is what the rule *is*."

4. **No-bind proof is an absence-proof, not a presence-proof.** Proving a
   negative ("no seal was issued") cryptographically requires binding the
   *absence* to a verifiable position in an append-only, hash-chained
   evidence stream (`evidence_stream.py`) — i.e., proving that between two
   known, signed evidence-stream sequence numbers, no `routing_seal`-typed
   record for this `action_hash` exists. This is structurally different from
   (and complementary to) `verify_seal()`'s job of validating a seal that
   *does* exist (§6.5).

5. **Formation boundary is explicit, not inferred.** Rather than leaving
   readers to infer "was this truly non-formed or was it rolled back?" from
   free-text (`protected_consequence`), a new `formation_boundary` enum
   (§6.3) makes the distinction a first-class, machine-checkable field:
   `NEVER_FORMED` | `FORMED_AND_ROLLED_BACK`. Regulatory and legal review
   requires this distinction to be unambiguous, not implied.

6. **Containment attestation references a static proof, not a per-transaction
   one.** `proof/model.py`'s BFS exhaustiveness proof is a **system-wide**
   invariant proof, computed once per deployed commit — it would be wasteful
   and misleading to re-run it per transaction. Instead the receipt embeds a
   `proof_artifact_digest` (SHA-256 of the proof script's fixed textual
   output, e.g. `"No-Direct-Bind holds over N reachable states: True"`) and
   the `deployed_commit_sha`, allowing an auditor to confirm the running
   binary matches the commit the proof was run against (§6.6).

---

## 6. `GovernanceRefusalReceipt` v3 — Complete JSON Schema

The schema is presented as nine numbered sub-objects, one per Terry proof
element, plus an envelope wrapper. All numeric/string/boolean leaf values are
JSON-serializable; the whole structure is JCS-canonicalized before hashing
and signing (§2.4).

### 6.0 Top-Level Structure

```json
{
  "receipt_version": "3.0",
  "receipt_id": "cage-refusal-<uuid>",
  "thread_id": "thread-abc123",
  "issued_at": "2026-08-23T10:00:00.000Z",
  "decision": "DENY",

  "intent": { "...": "§6.1" },
  "baseline": { "...": "§6.2" },
  "failure": { "...": "§6.3a" },
  "protection_proof": { "...": "§6.3b" },
  "no_bind_proof": { "...": "§6.5" },
  "containment_attestation": { "...": "§6.6" },
  "rule_snapshot": { "...": "§6.4" },

  "proof_hash": "sha256:<hex>",
  "envelope_signature": {
    "algorithm": "ES256",
    "kid": "<jwks-kid>",
    "value": "base64url(...)"
  }
}
```

`proof_hash` is the SHA-256 digest of the JCS-canonical bytes of every field
above it (i.e. everything except `proof_hash` and `envelope_signature`
itself) — directly mirroring
[`GovernanceEnvelope.compute_digest()`](../../src/gateway/governance/governance_envelope.py:277).
`envelope_signature` is populated by wrapping this receipt as a
`GovernanceEnvelope` payload and calling
`GovernanceEnvelopeBuilder.build()` (§5 decision 2) — the field shown inline
here for readability is, in the actual wire format, the envelope's own
`signature` block, and `proof_hash` corresponds to the envelope's
`subject.record_hash`.

### 6.1 `intent` — Proof Element 1 (Movement)

```json
"intent": {
  "action": "execute_trade",
  "attempted_params": {
    "symbol": "AAPL",
    "amount": 25000.00,
    "currency": "USD"
  },
  "action_hash": "sha256:<jcs-hash-of-action+params>",
  "agent_id": "treasury-agent-prod-v1",
  "requested_at": "2026-08-23T09:59:59.900Z"
}
```

- `attempted_params` — direct carry-forward of `RefusalReceipt.attempted_params`
  ([`contracts.py:76`](../../src/gateway/governance/contracts.py:76)).
- `action_hash` — **new**, computed with the same
  `jcs_canonicalize_plan({"action": action, **safe_params})` recipe already
  used by
  [`GovernanceEnvelopeBuilder._compute_action_hash()`](../../src/gateway/governance/governance_envelope.py:322)
  and [`routing_seal.py`'s action-hash check](../../src/gateway/governance/routing_seal.py:496) —
  reusing the identical hash lets a verifier confirm the receipt's `intent`
  matches what a *would-be* seal's `action_hash` claim would have been, had
  one been issued.

### 6.2 `baseline` — Proof Element 2 (Present Standing)

```json
"baseline": {
  "claimed_authority": "spiffe://cage.local/treasury-agent",
  "claimed_scope": ["execute_trade", "read_market_data"],
  "policy_version": "sha256:<ControlRegistry.active_hash>",
  "deployment_region": "US_FED",
  "standing_snapshot": {
    "symbol": "AAPL",
    "amount": 25000.00,
    "confidence": 0.62
  }
}
```

- `standing_snapshot` — direct carry-forward of
  `RefusalReceipt.standing_snapshot` /
  `GovernanceTierFailure.governing_state`
  ([`contracts.py:48`](../../src/gateway/governance/contracts.py:48)).
- `policy_version` — **new**, but trivially sourced: identical value to
  `GovernanceContext.policy_version`
  ([`governance_envelope.py:168`](../../src/gateway/governance/governance_envelope.py:168)),
  which already calls `ControlRegistry().active_hash`. This is the field
  that binds "what standing was claimed" to "under which compiled rule-set,"
  closing the traceability gap between proof elements 2 and 9.
- `claimed_authority` / `claimed_scope` — **new**, sourced from the SPIFFE ID
  and `agent_catalog.rego` scope lookup already performed by the OPA tier
  (Tier 4) before refusal; simply not currently copied into the receipt.

### 6.3a `failure` — Proof Element 3 (Lost Standing)

```json
"failure": {
  "control_id": "CTRL_CBF_002",
  "violated_rule": "h(S(t+1)) < (1-gamma)*h(S(t)): cash floor breach",
  "tier_failures": [
    {
      "tier": "CBF",
      "control_id": "CTRL_CBF_002",
      "rule_description": "Discrete-time Control Barrier Function invariant",
      "governing_state": { "cash_balance": 8000.00, "min_cash_balance": 10000.00 },
      "protected_consequence": "prevented balance from dropping below floor",
      "external_citation": "SP 800-53 SC-4 / SR 26-2 §IV.B"
    }
  ],
  "stpa_violation_count": 0
}
```

- `control_id`, `violated_rule`, `tier_failures[]` — direct carry-forward of
  `RefusalReceipt` v2 fields
  ([`contracts.py:69-81`](../../src/gateway/governance/contracts.py:69)).
- `tier_failures[].external_citation` — **new**, resolved via
  [`ControlRegistry.get_mapping(control)`](../../src/gateway/governance/constants.py:356)
  at receipt-build time (`primary_framework` field), giving each internal
  `CTRL_*` ID an external regulatory citation without embedding volatile
  strings in Python source (§2.11).
- **Design note:** schema v2 only stores the *first* failing
  `GovernanceTierFailure` in the top-level `control_id`/`violated_rule`
  fields (see [`symbolic_governor.py:1820-1821`](../../src/gateway/governance/symbolic_governor.py:1820),
  `_first_tf = _tier_failures[0]`). v3's `tier_failures[]` is the **full
  array already collected** in `result["tier_failures"]`
  ([`symbolic_governor.py:1819`](../../src/gateway/governance/symbolic_governor.py:1819)) —
  no new data collection is needed, only a change to what is copied into the
  receipt.

### 6.3b `protection_proof` — Proof Element 5 (Unformed Consequence)

```json
"protection_proof": {
  "formation_boundary": "NEVER_FORMED",
  "protected_consequence": "prevented balance from dropping below floor",
  "cbf_commit_occurred": false,
  "fiscal_reservation_occurred": false,
  "external_api_calls_made": [],
  "rollback_reference": null
}
```

- `formation_boundary` — **new** enum (§5 decision 5):
  - `NEVER_FORMED` — refusal occurred in Phase 1 (read-only checks: STPA,
    confidence, CBF *check* without commit, OPA) — see
    [`symbolic_governor.py`](../../src/gateway/governance/symbolic_governor.py:1144)
    "Phase 1 (no mutations)" comment. No state was ever written.
  - `FORMED_AND_ROLLED_BACK` — refusal occurred in Phase 2 *after*
    `atomic_verify_and_commit()` succeeded but a later tier (e.g. Fiscal)
    failed, triggering
    [`rollback_state()`](../../src/gateway/governance/cbf.py:1230). The
    `rollback_reference` field then points to the Redis
    `audit:state_ledger` entry proving the compensating transaction
    completed (§2.10).
- `cbf_commit_occurred` / `fiscal_reservation_occurred` — **new** booleans,
  directly derivable from which Phase 2 sub-step (if any) executed before
  the failure — this information already exists as local variables
  (`_cbf_committed`, `_fiscal_token`) in `_run_checks()`
  ([`symbolic_governor.py:1733`](../../src/gateway/governance/symbolic_governor.py:1733))
  but is currently discarded rather than recorded.
- `external_api_calls_made` — **new**, always `[]` for a true non-formation
  receipt; a non-empty list here would itself be evidence the claim does
  not hold (fail-loud design: the field exists specifically so its emptiness
  is asserted, not assumed).

### 6.4 `rule_snapshot` — Proof Element 9 (Changed-Condition Immutability)

```json
"rule_snapshot": {
  "rule_digest": "sha256:<ControlRegistry.active_hash at refusal time>",
  "deployment_region": "US_FED",
  "compliance_baseline_source": "config/compliance/US_FED_BASELINE.json",
  "rule_lineage": {
    "prev_rule_digest": "sha256:<hash of previously active baseline>",
    "lineage_hash": "sha256:<hash(prev_rule_digest + rule_digest + effective_from)>",
    "effective_from": "2026-08-01T00:00:00.000Z"
  }
}
```

- `rule_digest` — **new**, but a **direct read** of
  [`ControlRegistry().active_hash`](../../src/gateway/governance/constants.py:253),
  already computed and cached at every registry load
  ([`constants.py:328`](../../src/gateway/governance/constants.py:328)). No
  new hashing logic — only a new call site copying the existing value into
  the receipt.
- `rule_lineage` — **new** structure, modeled directly on
  [`ProvenanceRecord`](../../src/gateway/governance/provenance_chain.py:98)'s
  `parent_hash` / `chain_hash()` pattern (§2.3). Each time
  `ControlRegistry.reconfigure()`
  ([`constants.py:398`](../../src/gateway/governance/constants.py:398)) loads
  a new baseline, a new `rule_lineage` entry is appended to a
  **separate, independently-persisted rule-lineage log** (not part of any
  individual receipt) — receipts reference a lineage entry by
  `lineage_hash`, they do not embed the whole lineage history. This
  decoupling is what makes "changed-condition immutability" possible: a
  rule change appends to the lineage log and is reflected in *future*
  receipts' `rule_digest`, while every previously-issued receipt's
  `rule_snapshot` (and therefore its `proof_hash` and KMS signature) is
  **structurally incapable of being affected**, because the receipt only
  ever embedded a frozen digest value, never a live reference.
- `compliance_baseline_source` — the literal file path
  ([`constants.py:301`](../../src/gateway/governance/constants.py:301),
  `config/compliance/{REGION}_BASELINE.json`) for direct auditor
  cross-reference against the version-controlled Git history of that file.

### 6.5 `no_bind_proof` — Proof Element 4 (Block / No-Bind)

```json
"no_bind_proof": {
  "claim": "NO_ROUTING_SEAL_ISSUED",
  "evidence_stream_range": {
    "prev_hash_before_refusal": "sha256:<evidence_stream prev_hash at t-1>",
    "next_hash_after_refusal": "sha256:<evidence_stream record_hash at t+1, if any>",
    "sequence_start": 104213,
    "sequence_end": 104214
  },
  "seal_lookup_result": "ABSENT",
  "verification_method": "evidence_stream_range_scan"
}
```

- **Design rationale (§5 decision 4):** `verify_seal()`
  ([`routing_seal.py:435`](../../src/gateway/governance/routing_seal.py:435))
  and `verify_and_consume_seal()`
  ([`routing_seal.py:620`](../../src/gateway/governance/routing_seal.py:620))
  prove a seal **exists and is valid**. There is no existing negative-proof
  mechanism. The new `no_bind_proof` is built by querying the same
  hash-chained evidence stream
  ([`evidence_stream.py`](../../src/compliance_bridge/evidence_stream.py))
  that `routing_seal.py`'s
  [evidence-binding call](../../src/gateway/governance/routing_seal.py:334)
  writes to on **successful** seal issuance — for a refusal, the equivalent
  write **never happens**, so a range-scan between the last known-good
  `prev_hash` immediately before the refused request and the next
  chronological `record_hash` after it (which necessarily chains through
  the *unbroken* hash sequence, per
  [`verify_chain_integrity()`-style validation](../../src/gateway/governance/provenance_chain.py:227))
  constitutes cryptographic proof that no seal-issuance record was inserted
  in that window. Because the stream is append-only and hash-chained, an
  attacker cannot retroactively insert a seal record into this range without
  invalidating every subsequent hash — the absence-proof is exactly as
  strong as the presence-proof `verify_seal()` already relies on.
- `seal_lookup_result` — enum: `ABSENT` (expected/success case for a
  non-formation receipt) | `FOUND_UNEXPECTEDLY` (would indicate a critical
  invariant violation — a receipt in this state must never be issued and
  its generation should raise an internal alarm, since it would mean a seal
  was issued for an action later claimed to be refused).

### 6.6 `containment_attestation` — Proof Element 6 (Route Closure)

```json
"containment_attestation": {
  "proof_artifact": "proof/model.py",
  "proof_artifact_digest": "sha256:<hash of proof output text>",
  "invariant": "NoDirectBind == (phase = \"EXECUTED\") => (resolvedAllow = TRUE)",
  "reachable_states_verified": 66,
  "deployed_commit_sha": "88fa9d7...",
  "proof_last_run_at": "2026-08-20T00:00:00.000Z",
  "distributed_proof_artifact": "proof/distributed_cbf_model.py",
  "distributed_proof_digest": "sha256:<hash of distributed proof output>"
}
```

- This sub-object does **not** vary per-transaction — it is a **constant
  reference block** stamped onto every receipt issued while a given commit
  is deployed, analogous to how
  [`GovernanceContext.policy_version`](../../src/gateway/governance/governance_envelope.py:168)
  is constant across all envelopes issued under one active `ControlRegistry`
  load.
- `proof_artifact_digest` — **new**, computed once at CI/release time by
  hashing the deterministic textual output of
  [`proof/model.py`](../../proof/model.py:61) (`python proof/model.py`
  produces a fixed string per the module's own docstring:
  `"[gated] No-Direct-Bind holds over all N reachable states: True"`).
  Stored as a release artifact (e.g. alongside the SBOM,
  `scripts/generate_sbom.py`) and injected into the gateway's runtime
  environment at deploy time (e.g. `CAGE_PROOF_ARTIFACT_DIGEST` env var or a
  baked-in build metadata file), mirroring how `deployed_commit_sha` is
  typically injected via `CAGE_INSTANCE_ID`/build labels today.
- `distributed_proof_artifact` — references the multi-agent cross-Redis
  contention proof
  ([`proof/distributed_cbf_model.py`](../../proof/distributed_cbf_model.py))
  for deployments where cross-shard coordination is in scope — included
  because Terry's "no backdoors or alternate routes" claim must cover
  distributed race conditions, not just single-request interleavings (see
  the model-scope caveat at
  [`proof/model.py:13-36`](../../proof/model.py:13)).
- **Honesty constraint (mirrors §5.4 of the Provider 05 specification precedent):**
  this sub-object must **not** claim exhaustive coverage of the actuator
  seal-verification boundary itself — `proof/model.py`'s own docstring
  states the actuator's `verify_seal()` check is "a verified precondition
  in the routing_seal module... not modeled here because it is a distinct
  trust boundary." The receipt's `containment_attestation` should carry a
  `caveats: ["actuator_seal_verification_modeled_separately"]` array
  entry making this scope boundary explicit rather than implying a stronger
  guarantee than the underlying proof provides.

### 6.7 Persistence, Envelope Wrapping & WORM Storage — Proof Element 7 (Evidence/Receipt)

The complete receipt (§6.0-6.6) becomes the `payload` of a
`GovernanceEnvelope`:

```python
envelope = await builder.build(
    action=f"refusal_receipt:{intent.action}",
    params=receipt.to_dict(),  # the full 9-part structure
    governance_result={"decision": "DENY", "receipt_id": receipt.receipt_id},
    record_hash=receipt.proof_hash,
    agent_id=intent.agent_id,
    tiers_passed=[],  # none passed — this is a DENY
    controls_satisfied=[],  # none — refusal, not approval
    envelope_type=EnvelopeType.GOVERNANCE_DECISION,  # or new REFUSAL_RECEIPT type
)
```

This reuses [`GovernanceEnvelopeBuilder.build()`](../../src/gateway/governance/governance_envelope.py:437)
unmodified — the same KMS-signing path
([`sign_precomputed_digest()`](../../src/gateway/governance/kms_signer.py:624))
used for ALLOW decisions today also signs DENY receipts, satisfying the
"immutable signed hash proving all above" requirement with **zero new
signing code**.

**Persistence path (new):** the signed envelope is written to a
CMEK-encrypted GCS WORM bucket at
`gs://<bucket>/refusal-receipts/<date>/<receipt_id>.json`, following the
exact convention already documented for provenance records
(`provenance/<date>/<trace_id>.json`, see
[`provenance_chain.py:22`](../../src/gateway/governance/provenance_chain.py:22))
and evidence-stream batches
([`evidence_stream.py`'s `_upload_to_gcs()`](../../src/compliance_bridge/evidence_stream.py:1282)).
No new storage backend is introduced — this is a new object-key prefix
within the existing `src/compliance_bridge/storage.py` GCS/S3 abstraction
([`upload_artifact()`](../../src/compliance_bridge/storage.py:281)), giving
the receipt the same CMEK guarantee already verified by
[`cmek_guard.py`](../../src/compliance_bridge/cmek_guard.py:29) for OSCAL
artifacts.

---

## 7. Cryptographic Flow Diagram

### 7.1 End-to-End Refusal → Receipt → WORM Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. AGENT REQUEST                                                         │
│    action="execute_trade", params={amount: 25000, symbol: "AAPL"}       │
└───────────────────────────────┬───────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 2. SymbolicGovernor._run_checks()  (Tiers 0.5 → 6b)                     │
│    STPA → confidence → CBF(check) + OPA(concurrent) → fiscal → consensus │
│    → causal → FRIA                                                      │
│    Each failing tier emits GovernanceTierFailure(tier, control_id,      │
│      rule_description, governing_state, protected_consequence)          │
└───────────────────────────────┬───────────────────────────────────────┘
                                 │ violations non-empty
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 3. GovernanceError raised BEFORE generate_seal_with_evidence() reached   │
│    (symbolic_governor.py:1853 vs :1865 — structural ordering IS the      │
│    no-bind guarantee: seal issuance code is textually unreachable        │
│    on this path)                                                         │
└───────────────────────────────┬───────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 4. GovernanceRefusalReceipt v3 ASSEMBLY (new)                            │
│    ┌──────────┐ ┌──────────┐ ┌─────────┐ ┌──────────────────┐          │
│    │ intent   │ │ baseline │ │ failure │ │ protection_proof │  ...     │
│    └──────────┘ └──────────┘ └─────────┘ └──────────────────┘          │
│    ┌─────────────┐ ┌────────────────────────┐ ┌───────────────┐        │
│    │rule_snapshot│ │containment_attestation │ │ no_bind_proof  │        │
│    └─────────────┘ └────────────────────────┘ └───────────────┘        │
│         (rule_digest = ControlRegistry().active_hash, READ-ONLY)        │
│         (no_bind_proof = evidence_stream range-scan, ABSENT expected)   │
└───────────────────────────────┬───────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 5. JCS CANONICALIZATION                                                  │
│    canonical_bytes = jcs_canonicalize_plan(receipt.to_dict())            │
│    proof_hash = SHA-256(canonical_bytes)                                 │
│    (RFC 8785 — deterministic across Python/Go/Rust/Java forever)         │
└───────────────────────────────┬───────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 6. ENVELOPE WRAP  (GovernanceEnvelopeBuilder.build_unsigned)             │
│    envelope.payload = receipt.to_dict()                                 │
│    envelope.subject.record_hash = proof_hash                            │
│    digest = envelope.compute_digest()   # SHA-256 of full envelope       │
└───────────────────────────────┬───────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 7. KMS SIGNING  (KMSGovernanceSigner.sign_precomputed_digest)            │
│    Private key NEVER leaves HSM (GCP KMS / AWS KMS / Azure Managed HSM)  │
│    signature = HSM.asymmetric_sign(digest)                              │
│    envelope.signature = {algorithm, kid, value}                         │
│    (fail-closed: no HMAC fallback in production — kms_signer.py:851)    │
└───────────────────────────────┬───────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 8. WORM PERSISTENCE                                                      │
│    gs://<CMEK-bucket>/refusal-receipts/<date>/<receipt_id>.json          │
│    (append-only object; CMEK-verified via cmek_guard.py)                 │
└───────────────────────────────┬───────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 9. EXTERNAL VERIFICATION (auditor, regulator, court — any time later)    │
│    a. Fetch receipt JSON from WORM bucket                                │
│    b. Fetch verification key: GET /jwks → JWKSet.get_pem(kid)            │
│    c. Recompute canonical_bytes = JCS(receipt payload)                   │
│    d. Recompute digest = SHA-256(canonical_bytes + envelope fields)      │
│    e. Verify signature against public key (ECDSA/RSA/Ed25519)            │
│    f. [OPTIONAL] Replay: re-run _run_checks() against rule_snapshot +    │
│       intent.attempted_params → assert identical tier_failures[]         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Key Cryptographic Properties by Layer

| Layer | Guarantee | Mechanism |
|---|---|---|
| Canonicalization | Deterministic bytes regardless of platform/language | RFC 8785 JCS ([`jcs_canonicalizer.py`](../../src/gateway/governance/jcs_canonicalizer.py:24)) |
| Hashing | Tamper-evidence — any field change invalidates `proof_hash` | SHA-256 over JCS bytes |
| Signing | Non-repudiation — CAGE application code cannot forge a valid signature | Asymmetric HSM signing, private key never exported ([`kms_signer.py`](../../src/gateway/governance/kms_signer.py:391)) |
| Key distribution | Any external party can independently verify without trusting CAGE's runtime | Public JWKS endpoint ([`jwks.py`](../../src/gateway/governance/jwks.py:363)) |
| Persistence | Immutability — receipt cannot be altered or deleted post-write | CMEK-encrypted GCS WORM bucket ([`storage.py`](../../src/compliance_bridge/storage.py:281), [`cmek_guard.py`](../../src/compliance_bridge/cmek_guard.py:29)) |
| No-bind evidence | Absence of a seal is itself cryptographically provable | Hash-chained append-only evidence stream range-scan ([`evidence_stream.py`](../../src/compliance_bridge/evidence_stream.py)) |
| Rule provenance | Rule value at refusal time is frozen and independently auditable | Content-addressed `rule_digest` decoupled from receipt signature ([`constants.py`](../../src/gateway/governance/constants.py:253)) |
| Containment | System-wide absence of alternate execution routes | Static BFS exhaustive proof, referenced by digest ([`proof/model.py`](../../proof/model.py:42)) |

---

## 8. Immutability Guarantee Specification

### 8.1 Same-Condition Immutability (Proof Element 8)

**Claim:** A receipt issued today must replay to the identical refusal
outcome ten years from now, assuming the same rule-set and inputs.

**Mechanism — the Replay Procedure:**

1. Extract `intent.attempted_params`, `intent.action`, and
   `baseline.deployment_region` from the archived receipt.
2. Extract `rule_snapshot.rule_digest` and, using the version-controlled
   Git history of `rule_snapshot.compliance_baseline_source`
   (§6.4), locate and check out the **exact historical JSON file** whose
   content hash equals `rule_digest`.
3. Instantiate a `ControlRegistry` against that historical file
   (`ControlRegistry.reconfigure()` accepts an explicit region/path in the
   design — see §9 open question on a `from_file()` override) rather than
   the live environment's active registry.
4. Re-run `SymbolicGovernor._run_checks(action, attempted_params)` against
   this frozen registry.
5. Assert the newly-produced `tier_failures[]` array is **structurally
   identical** (same `control_id`, `tier`, `rule_description` per entry —
   `governing_state` values may legitimately differ if they reference
   *external* live state like account balances, which is why
   `standing_snapshot` is captured as a **point-in-time value**, not
   re-derived) to `failure.tier_failures[]` in the archived receipt.
6. Recompute `proof_hash` over the archived receipt's own fields and confirm
   it matches the stored value; recompute the envelope digest and verify the
   KMS signature against the historical `kid`'s public key (fetched from the
   **retained** JWKS history, not the current live JWKS — see requirement
   below).

**Requirements this places on other components:**
- **JWKS retention:** unlike the routing-seal JWT verification path (which
  only needs recently-rotated keys within a short grace window,
  [`jwks.py:292`](../../src/gateway/governance/jwks.py:292)), the receipt
  verification path requires **indefinite retention** of retired public
  keys (or their PEM material in cold storage) — a policy requirement on
  key-rotation operations (see
  [`docs/operations/KEY_ROTATION.md`](../operations/KEY_ROTATION.md)),
  not a code change to `JWKSet` itself. `JWKSet`'s `_JWKS_MAX_KEYS` eviction
  (default 3, [`jwks.py:57`](../../src/gateway/governance/jwks.py:57))
  governs the **live verification** JWKS only; an **archival JWKS**
  (append-only, never evicts) is a separate, new artifact this design
  requires but does not itself define the storage mechanics for (flagged as
  an open question, §9).
- **Git history immutability for compliance baselines:** `config/compliance/
  {REGION}_BASELINE.json` files must never be force-pushed or rewritten —
  this is already implicit in the branch-protection rules for `main`
  (squash-merge only, per [`AGENTS.md`](../../AGENTS.md)) but should be
  called out explicitly as a dependency of receipt replayability.
- **JCS stability:** RFC 8785 is a finalized IETF RFC with no planned
  revisions; the `jcs` library dependency
  ([`vendor/jcs`](../../src/gateway/governance/vendor/jcs)) is vendored
  in-tree specifically to avoid upstream drift affecting historical
  hash reproducibility.

### 8.2 Changed-Condition Immutability (Proof Element 9)

**Claim:** When the underlying rule/threshold changes, new receipts reflect
the new rule; every receipt issued under the old rule remains valid,
unaltered, and independently verifiable.

**Mechanism — Rule-Snapshot / Receipt Decoupling:**

The critical invariant is: **a receipt's cryptographic validity depends only
on its own frozen `rule_snapshot.rule_digest` field, never on the live state
of `ControlRegistry`.** This is enforced structurally, not just by
convention:

1. `rule_snapshot.rule_digest` is computed **once**, at receipt-assembly
   time, by reading `ControlRegistry().active_hash`
   ([`constants.py:253`](../../src/gateway/governance/constants.py:253)) —
   a plain value copy, not a live reference or pointer.
2. This value is included in the JCS-canonicalized bytes that produce
   `proof_hash` (§6.0) — meaning **the digest is baked into the very hash
   that the KMS signature covers**. Any subsequent change to the live
   `ControlRegistry` (via
   [`ControlRegistry.reconfigure()`](../../src/gateway/governance/constants.py:398))
   has **zero causal path** back to an already-signed receipt's bytes — the
   receipt object is immutable Python (`frozen=True` dataclass pattern,
   matching [`RefusalReceipt`](../../src/gateway/governance/contracts.py:52)),
   and the WORM storage layer (§6.7) additionally enforces this at the
   infrastructure level (object-lock / retention policy on the GCS bucket).
3. When a rule changes, `ControlRegistry.reconfigure(region)` performs an
   **atomic swap** ([`constants.py:439-443`](../../src/gateway/governance/constants.py:439))
   of the singleton's `_mappings` and `_active_hash` — this affects only
   **future** `_run_checks()` invocations and future receipts' `rule_digest`
   values. No existing receipt object is touched, because receipts are never
   re-serialized or re-hashed after issuance; they are write-once artifacts
   in WORM storage.
4. The **rule lineage log** (§6.4) — a separate, append-only chain
   (following the `ProvenanceRecord.parent_hash` pattern, §2.3) — records
   the sequence of `rule_digest` values over time with `effective_from`
   timestamps. This lets an auditor answer "what rule was active when
   receipt X was issued, and how does that compare to the rule active
   today" **without needing to trust any single receipt's self-reported
   `rule_digest`** — the lineage log is independently signed and chained,
   providing a second, cross-checkable source of truth.

**Why this is not merely a convention but a structural guarantee:**

| Attack / Failure Mode | Why It Cannot Succeed |
|---|---|
| Operator edits `config/compliance/US_FED_BASELINE.json` after a receipt was issued, hoping to retroactively "justify" the receipt under new rules | The receipt's `rule_digest` is a **frozen hash of the file's old content**, embedded in a KMS-signed, WORM-stored artifact. The edited file produces a *different* hash; the receipt's signature does not change to match, so re-verification via the replay procedure (§8.1) would either fail (if compared against the *new* file) or succeed (if compared against the *archived* historical file, retrieved via Git history) — either way, the discrepancy is externally detectable, not silently absorbed. |
| Operator attempts to "patch" an already-issued receipt in WORM storage to reflect a rule change | GCS object-lock / WORM retention policy (§6.7, extending [`cmek_guard.py`](../../src/compliance_bridge/cmek_guard.py:29)'s existing CMEK verification pattern) makes the object immutable at the storage layer for its retention period; even with write access, any byte change invalidates `proof_hash` and the KMS `envelope_signature`, which any verifier (§7.1 step 9) would immediately detect. |
| A new rule is deployed, and old receipts are expected to be "upgraded" to reflect it | This is a **conceptual non-goal** — receipts are point-in-time facts, not live policy statements. The `rule_lineage` chain (§6.4) is the correct mechanism for representing "the rule changed on date X"; individual receipts are never mutated to match. |

### 8.3 Summary Table — Immutability Requirements per Proof Element

| Proof Element | What Must Never Change | What Is Allowed/Expected to Change Over Time |
|---|---|---|
| 8 (same-condition) | `intent`, `baseline.standing_snapshot`, `failure.tier_failures[]`, `proof_hash`, `envelope_signature` | Nothing — full byte-for-byte replay must reproduce identical output |
| 9 (changed-condition) | Every previously-issued receipt's `rule_snapshot.rule_digest` and all downstream hashes/signatures | `ControlRegistry.active_hash` (future receipts only); `rule_lineage` log grows (append-only) |

---

## 9. Open Questions & Risk Register

| # | Question / Risk | Discussion |
|---|---|---|
| 1 | Should `GovernanceRefusalReceipt` be a new `EnvelopeType.REFUSAL_RECEIPT` or reuse `GOVERNANCE_DECISION`? | Reuse minimizes code paths but conflates ALLOW/DENY envelope semantics in downstream consumers (e.g. dashboards) that filter by `envelope_type`. A new sibling type is cleaner but touches the `EnvelopeType` enum ([`governance_envelope.py:104`](../../src/gateway/governance/governance_envelope.py:104)) and any code that pattern-matches on it. Recommend the new-type approach for clarity, deferred to implementation phase. |
| 2 | Where does the "archival JWKS" (indefinite key retention, §8.1) live? | Not addressed by existing `JWKSet` (which is designed for short-lived rotation). Likely a new, append-only, WORM-stored key-history artifact, separate from the live `/jwks` endpoint. Needs a dedicated design pass — flagged, not resolved, here. |
| 3 | Does `ControlRegistry` need a `from_file(path)` classmethod for offline replay (§8.1 step 3)? | Currently `_load_registry()` resolves paths internally from `CAGE_DEPLOYMENT_REGION`; replay tooling run outside a live CAGE deployment (e.g. by an external auditor) needs a way to instantiate a registry against an arbitrary historical file without environment-variable coupling. This is a small, additive API surface change — design only, not scoped for this document. |
| 4 | Performance impact of `no_bind_proof`'s evidence-stream range-scan on every DENY? | The evidence stream is already hash-chained and append-only; a range-scan between two known sequence numbers is O(1) lookups (both boundary hashes are already known — the request itself brackets them), not a full-stream scan. Should be validated empirically during implementation, not assumed here. |
| 5 | Should `rule_lineage` be a new standalone service, or an extension of `provenance_chain.py`? | `provenance_chain.py` currently models per-transaction node chains, not policy-version chains. A separate, purpose-built `rule_lineage_chain.py` module (reusing `ProvenanceRecord`'s pattern but not its code, since the domain differs — policy versions vs. transaction nodes) is architecturally cleaner. Flagged for implementation-phase design. |
| 6 | Regional variation: does a `PAUSE`-timing-out-to-DENY receipt need a distinct `formation_boundary` value? | Not addressed in §6.3b's two-value enum. A `PAUSE_EXPIRED` sub-case may be needed if the pre-pause and post-timeout system states could differ (e.g. a resource that was reserved during the pause window and must be explicitly shown as released). Flagged as a possible third `formation_boundary` enum value for implementation-phase refinement. |
| 7 | OSCAL emission of non-formation receipts — new artifact type or extend `oscal_ssp_exporter.py`? | The existing OSCAL exporter targets SSP/component-definition artifacts, not per-transaction evidence. A regulator-facing bulk export of refusal receipts (e.g. "show me every SC-4 refusal in Q3") is a plausible compliance ask but is a **new** aggregation/export tool, not a natural extension of `oscal_ssp_exporter.py`'s current scope. Out of scope for this document; flagged for a follow-on design. |

---

## 10. Conclusion

Terry Snyder's 9-part burden of proof is not a new cryptographic invention
for CAGE — it is a **formalization and completion** of evidentiary patterns
CAGE already implements piecemeal: JCS canonicalization
([`jcs_canonicalizer.py`](../../src/gateway/governance/jcs_canonicalizer.py)),
KMS-backed non-repudiation
([`kms_signer.py`](../../src/gateway/governance/kms_signer.py)), hash-chained
provenance ([`provenance_chain.py`](../../src/gateway/governance/provenance_chain.py)),
and a structural (not merely policy-based) No-Direct-Bind invariant
([`proof/model.py`](../../proof/model.py)). Five of the nine proof elements
(1, 2, 3, 7-partial, 8-partial) already have direct field-level analogues in
the existing `RefusalReceipt` schema v2
([`contracts.py`](../../src/gateway/governance/contracts.py:52)); the
remaining work is compositional — wrapping the existing receipt as a signed,
WORM-persisted `GovernanceEnvelope`, and adding four genuinely new
sub-objects (`no_bind_proof`, `protection_proof.formation_boundary`,
`containment_attestation`, `rule_snapshot`/`rule_lineage`) that make the
implicit non-formation claim explicit, machine-verifiable, and independently
replayable a decade after issuance.

No new cryptographic primitive is required. No new trust boundary is
introduced. The design's entire strength derives from **composing existing,
already-audited CAGE mechanisms in a new arrangement**, which is itself a
desirable property for a compliance-critical artifact: every cryptographic
building block in `GovernanceRefusalReceipt` v3 has already been reviewed,
tested, and deployed in production for a different purpose, minimizing the
net-new attack surface this design introduces.
