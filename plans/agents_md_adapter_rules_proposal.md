# Proposed `AGENTS.md` Additions — Partner Adapter Design Rules

**Derived from:** the 2026-09-09 execution of
[`consolidated_implementation_plan_2026-09-09.md`](consolidated_implementation_plan_2026-09-09.md)
— 26 items, 14 branches, 3839 → 3921 tests.

> **Status update 2026-09-09 — the recommended subset has been APPLIED to
> [`AGENTS.md`](../AGENTS.md).** Four rule groups are now binding:
>
> | Rule | Location |
> |---|---|
> | Trust Anchors — Never Verify Against an Embedded Key | [`AGENTS.md:472`](../AGENTS.md:472) |
> | Resolution Status Is Not Verification Status | [`AGENTS.md:473`](../AGENTS.md:473) |
> | Refusals Are Primary Evidence | [`AGENTS.md:474`](../AGENTS.md:474) |
> | Verification Rules — full-gate, merge-base attribution, grep-after-rename | [`AGENTS.md:546`](../AGENTS.md:546) |
>
> *Resolution Status* was included alongside *Trust Anchors* because the two are
> one contract: the first says where a key comes from, the second says what a
> successful fetch does and does not prove. Separated, an implementer can satisfy
> either while defeating the intent of both.
>
> **Everything else in Part 2 remains deferred by design** — not forgotten. The
> rest should follow only once these four have proven useful in review. Do not
> bulk-apply the remainder; each addition competes for a reader's attention with
> the rules already there.

**Status:** the remaining rules are a proposal for review. Nothing here is
speculative; every rule corresponds to a defect that actually occurred, with the
site named. Rules without an incident behind them have been left out
deliberately — a standards document that grows by intuition stops being read.

**Placement:** §"External Vendor Adapter Standards (Plugin Architecture)"
([`AGENTS.md:461`](../AGENTS.md:461)) for the adapter rules; the verification
rules extend §"Test Execution" ([`AGENTS.md:530`](../AGENTS.md:530)).

---

## Part 1 — Lessons learned

Five defects reached a branch head despite every subtask reporting green. Each
generalizes.

### L1 — "Built and tested" is not "reachable"

Twice in one day, a feature existed with passing tests and **never executed**.

`build_oscal_assessment_results()` accepted `cer_uris` and emitted
`rel="evidence"` links, covered by seven passing tests. The only production
caller never passed the argument. **Zero links were emitted at runtime.**

The remediation PR rebuilt the plumbing — Protocol, concrete index, disclosure
enum, exporter parameter — and *again* deferred the caller wiring as "future
work". State went from "built, tested, unreachable" to "built twice, tested
twice, still unreachable."

**Why the tests did not catch it:** they exercised the exporter directly. A unit
test of a function that nothing calls passes forever.

> **Rule:** a feature is not complete until a test exercises it through its
> production entry point. Where a component is injected, at least one test must
> assert the injected path produces the expected output — not merely that the
> component works when constructed by hand.

### L2 — A partial rename is worse than no rename

`DeferReason.FLOWSIGNAL_ESCALATION` → `EXTERNAL_HOLD` was applied to the enum and
its emitter but missed two consumers:

- [`governance_middleware.py`](../src/gateway/server/governance_middleware.py) compared
  `defer_reason == "FLOWSIGNAL_ESCALATION"` — **a condition that could no longer
  match.** The HTTP 202 escalation path survived only via a secondary boolean.
  An external-hold DEFER arriving without that marker silently returned 200, and
  the client never learned it must poll for human review. **A fail-open on a
  human-in-the-loop path.**
- [`compliance_bridge/main.py`](../src/compliance_bridge/main.py) kept the dead member
  in a quorum-3 injection gate — `AttributeError` on a governance control.

Both compiled. Both passed their own tests. Neither worked.

> **Rule:** after renaming any symbol crossing a module boundary, run
> `rg -n '<old_symbol>' src/` and require **zero** results before declaring
> done. Comparison against a string literal is invisible to the type checker;
> only the grep finds it.

### L3 — Required-field additions break silently outside their own package

Adding a required `provider_name` to `ExternalAttestation` broke
[`warrant.py:364`](../src/integrations/provider_05/warrant.py:364) — **production
code**, a runtime `TypeError` on every `bind_warrant_to_attestation` call. The
originating subtask ran only its own package's tests.

The same change was applied by a scripted edit that inserted the field into
constructor calls for **other classes entirely**, producing four collection
errors and leaving tell-tale mangled indentation.

> **Rule:** when adding a required field to a shared dataclass, enumerate every
> construction site with `rg -n '<ClassName>\('` across `src/` **and** `tests/`
> before editing. Never apply such a change by scripted find-and-replace —
> constructor calls for different classes look alike enough to fool a regex, and
> the failure surfaces at runtime rather than at type-check.

### L4 — Scope-local verification is not verification

Every one of the 25 failures was introduced by a subtask that ran only its own
test files and reported green. A later subtask then characterised them as
*"pre-existing, unrelated"* — disproved by running the same eight files on
pristine `main`: **104 passed, 1 skipped.**

Two failure modes compounded: incomplete verification created the defects, and
an unverified assumption nearly let them ship.

> **Rule:** a change is not green until the full `make test-fast` gate passes,
> not merely the tests in the touched package. When attributing a failure to
> pre-existing state, **verify against the merge base** and quote the result.
> "Pre-existing on my branch" and "pre-existing on `main`" are different claims.

### L5 — A security guard with no test is indistinguishable from no guard

Real Ed25519 verification shipped with **zero passing coverage**. The only tests
touching that path asserted the "not yet implemented" behaviour it had
superseded, so they errored and were assumed obsolete. The fail-closed invariant
still held — but nothing observed it.

Separately, the aggregator's quorum-3 injection gate had a test that was a bare
`pass  # TODO`. That empty test is precisely why L2's dead-enum defect reached a
branch head unchallenged.

> **Rule:** every fail-closed path needs a test that observes it **failing**. A
> test asserting only the happy path proves the mechanism runs, not that it
> blocks. A placeholder test is worse than no test: it makes a coverage report
> claim protection that does not exist.

### L6 — Cheap gates catch defect classes that review does not

The hardcoded Layer 4 node names in a Layer 3 adapter passed every existing gate
because `check_import_boundaries.py` scans for illegal **imports**, and the
coupling was **string literals**. The adapter worked for exactly one application;
any other adopter got an empty bundle, silently.

Fixing the instance without fixing the class would have let it return.

> **Rule:** when a defect escapes CI, ask what gate would have caught it and
> whether that gate is cheap. Extending an existing AST checker is usually an
> afternoon. Prefer that to a review checklist item, which decays.

---

## Part 2 — Proposed `AGENTS.md` rules

Written to slot into §"External Vendor Adapter Standards" in the existing voice.

### Trust anchors and key resolution

> **Never verify a signature against a key supplied by the signed document.** A
> forged receipt controls its entire body, including any embedded public key —
> verifying against it proves nothing. Resolve keys by `kid` from an
> independently-fetched key manifest, cached out-of-band.
>
> Enforce this **in the type system**, not in review comments: the verification
> function must accept a resolved key object, and only the cache lookup may
> produce one. An embedded key may be compared for diagnostics and logged on
> mismatch, but must never reach the verifier.
>
> On unknown `kid`: refresh the manifest **once**, then fail closed. Never fall
> back to the embedded key; never downgrade to a warning.

### Resolution status is not verification status

> A successful fetch proves a receipt **exists and is well-formed**. It does not
> prove the signature. Adapters must return `UNVERIFIED` on successful
> resolution and promote to `VERIFIED` only after cryptographic verification
> succeeds.
>
> Where verification is not yet implemented, the adapter must return `UNVERIFIED`
> — never `VERIFIED` with a comment promising a later fix.

### Make invalid states unrepresentable

> Where two fields have a safety-relevant relationship — a `valid` flag and a
> `signature_checked` flag, for example — enforce it in `__post_init__` rather
> than by convention. `CERVerification` raises when `valid=True` accompanies
> `signature_checked=False`, so the fail-open combination cannot be constructed
> at all.
>
> A convention is a request; a constructor invariant is a guarantee. Prefer the
> guarantee wherever the consequence of violation is a fail-open.

### Absent evidence is not fabricated evidence

> Many resolvers return an identical `404` for *unknown* and for
> *private/hidden*. Finding messages must say **unresolvable** — never *absent*,
> *missing*, *invalid*, or anything a reader could take as an accusation.
>
> CAGE must not accuse an adopter of fabricating evidence that merely happens to
> be private.

### Empty is not the same as absent

> Do not emit an empty string for a field whose mechanism did not run. An empty
> `kms_signature` invites the reader to assume signing occurred and returned
> nothing. **Omit the field**, so its absence is legible.
>
> Verify first that omission does not alter canonical bytes for any hashed
> payload. A silent hash change in an evidence chain is far worse than a
> misleading empty string.

### No application vocabulary in adapters

> Layer 3 adapters must not hardcode Layer 4 node names, graph topologies, or
> domain field names. CAGE ships **zero built-in applications**; the reference
> applications are demos, not definitions.
>
> Accept graph topology and field lists as **required** constructor arguments,
> supplied by the domain plugin. A default drawn from a reference application
> preserves exactly the silent-wrong-answer behaviour the injection removes.
>
> Classification helpers must **raise** on unrecognized input rather than
> defaulting. An unclassifiable traversal is an integrity signal, not a happy
> path.

### Adapters receive dependencies; they do not fetch them

> An adapter calling a kernel singleton accessor is service-locator — the
> inverse of dependency injection — and makes the adapter untestable without
> patching kernel global state.
>
> Accept dependencies as constructor parameters, typed to the **narrowest
> sufficient abstraction**. The composition root resolves singletons.
>
> Cryptographic operations belong in the kernel. Apply the decision test: *if two
> domains had different copies of this, would a security fix have to be applied
> twice?* Token minting is canonicalization plus signing — Layer 1 work. The
> adapter supplies claims as plain data; the kernel mints and signs.

### Vendor identity belongs in prose

> Vendor names are legitimate in READMEs, docstrings, comments, and Layer 3
> adapter identifiers — that is provenance. They are **coupling** in kernel enum
> members, string literals, Redis keys, and environment variables.
>
> Decision test: *if the vendor disappeared tomorrow, would this line have to
> change for the code to keep working?* Yes → refactor. No → keep.
>
> Where a vendor name is load-bearing in a wire contract — a required header, a
> signing domain tag — anonymization is unavailable without a coordinated
> protocol change. Document the constraint rather than attempting the rename.

### Registration validates; it does not defer

> Registries must reject non-conforming providers at `register()` with a
> `TypeError` naming both the offending type and the required protocol. Deferring
> validation to first use relocates the failure far from its cause, into error
> handling, at attestation-gathering time.
>
> Test doubles must be genuine subclasses or `spec=`-constrained mocks. Do not
> weaken the check to accommodate a loose fixture.

### Distinguish partial failure from total failure

> On total fetch failure, retain the prior cache, leave the last-success
> timestamp **unchanged**, and surface an explicit staleness signal. Advancing
> the timestamp over a fully-failed poll makes a dead provider indistinguishable
> from a healthy one to anything watching freshness.
>
> Capture provider identity **before** the `try`. A provider whose identity
> property itself raises must not abort the fetch loop and drop every subsequent
> provider.
>
> Carry provider identity in a first-class field. Encoding it into a type field
> as `PROVIDER_ERROR:{name}` makes error entries discoverable only by string
> prefix matching.

### Refusals are primary evidence

> A governance engine's refusals are the proof it intervened. If only ALLOW
> decisions reliably enter the tamper-evident chain, the audit record
> systematically over-represents permitted actions, and an auditor must take the
> operator's unsigned word on every block.
>
> DENY and PAUSE receipts must enter the evidence chain with the same
> completeness as approvals — the full proof object, not a lossy summary.
> Serialize the real object from one path rather than rebuilding a summary at
> each call site.
>
> **Ordering constraint:** wire evidence *citations* only after the chain they
> cite is complete. Emitting `link[rel="evidence"]` into a chain missing every
> DENY produces references to an incomplete record — worse than emitting none,
> because it looks complete.

---

## Part 3 — Verification rules (extends §Test Execution)

> **Full-gate before green.** A change is not complete until
> `make test-fast` passes across the whole suite. Running only the touched
> package's tests is how contract drift reaches a branch head.
>
> **Attribute failures to the merge base.** Before characterising a failure as
> pre-existing, run the affected files on the merge base and quote the result.
>
> **Grep after renaming.** `rg -n '<old_symbol>' src/` must return zero before a
> cross-module rename is done. String comparisons are invisible to `mypy`.
>
> **Enumerate construction sites before adding a required field.** Use
> `rg -n '<ClassName>\('` across `src/` and `tests/`. Never scripted
> find-and-replace.
>
> **Every fail-closed path needs a test that observes it failing.** Happy-path
> coverage proves the mechanism runs, not that it blocks.
>
> **Never leave a placeholder test.** A bare `pass  # TODO` under a meaningful
> name is worse than an absent test — it reports protection that does not exist.
> Prefer `pytest.skip` with a reason, which is visible in the summary.
>
> **Reset kernel singletons in teardown.** A mock leaking into a global produces
> order-dependent failures that pass in isolation and flake under `-n auto` —
> CI passing and failing on identical code.

---

## Recommended subset

If the full set is too much for one edit, these four have the highest
incident-to-words ratio:

1. **Trust anchors** — prevents a complete verification bypass
2. **Full-gate before green** — would have caught all 25 failures at introduction
3. **Grep after renaming** — would have caught the fail-open escalation path
4. **Refusals are primary evidence** — the roadmap's highest-priority item, and a
   principle rather than a fix

The rest can follow once these have proven useful in review.
